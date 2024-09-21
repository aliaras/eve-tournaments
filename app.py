# -*- encoding: utf-8 -*-
from datetime import datetime

from esipy import EsiApp
from esipy import EsiClient
from esipy import EsiSecurity
from esipy.exceptions import APIException

from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for

from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy import UniqueConstraint
from sqlalchemy import func

import config
import hashlib
import hmac
import logging
import random
import time

# logger stuff
logger = logging.getLogger(__name__)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
logger.addHandler(console)

# init app and load conf
app = Flask(__name__)
app.config.from_object(config)

# init db
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# init flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# -----------------------------------------------------------------------
# Database models
# -----------------------------------------------------------------------
class Tournament(db.Model):
    tournament_id = db.Column(
            db.Integer,
            primary_key=True,
            )
    tournament_owner=db.Column(db.Integer, db.ForeignKey('user.character_id'), nullable=False)
    tournament_name = db.Column(db.String(255))
    tournament_description = db.Column(db.String(1024))
    tournament_url = db.Column(db.String(255))
    tournament_type = db.Column(db.String(40))
    current_match_id=db.Column(db.Integer, db.ForeignKey('match.match_id'), nullable=True)
    current_match=db.Relationship("Match", foreign_keys='Tournament.current_match_id')
    players = db.relationship('Player', foreign_keys='Player.tournament_id', backref='tournament')
    team_size = db.Column(db.Integer)
    matches = db.relationship('Match', foreign_keys='Match.tournament_id', backref='tournament')

class Match(db.Model):
    match_id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.tournament_id'), nullable=False)
    red_team_name = db.Column(db.String(255))
    red_team_members = db.Column(db.String(2048)) #a list of character ids, comma separated
    blue_team_name = db.Column(db.String(255)) #a list of character ids, comma separated
    blue_team_members = db.Column(db.String(2048))

    #returns a list of character ids
    def get_red_players(self):
        return(self.red_team_members.split(','))

    def get_blue_players(self):
        return(self.blue_team_members.split(','))

class Player(db.Model):
    competitor_id = db.Column(db.Integer, primary_key=True)
    character_id = db.Column(db.Integer)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.tournament_id'), nullable=False)
    active = db.Column(db.Integer)
    wins = db.Column(db.Integer)
    losses = db.Column(db.Integer)
    matches = db.Column(db.Integer)

class SoloQueue(Tournament):
    def join_lobby(self, character):
        lobby_member_list = [s for s in self.players if s.character_id==character]

        #if this is a new entrant, create a Player record for them
        if len(lobby_member_list) == 0:
            lobby_member = Player(character_id=character,tournament_id=self.tournament_id,active=1,wins=0,losses=0,matches=0)

        #If they were inactive, set them back to active. If they were already active & in the tournament, this is a no-op
        elif len(lobby_member_list) == 1:
            lobby_member = lobby_member_list[0]
            lobby_member.active = 1

        #TODO complain if there's >1 entry in the lobby for this character
        db.session.merge(lobby_member)
        db.session.commit()
    
    # We leave lobbies by setting the player's active flag to 0. This allows them to rejoin with their metadata intact.
    def leave_lobby(self, character):
        lobby_member_list = [s for s in self.players if s.character_id==character]
        lobby_member = lobby_member_list[0]
        lobby_member.active = 0
        db.session.merge(lobby_member)
        db.session.commit()

    def pick_players_from_lobby(self):
       #Get all competitors in the tournament
       lobby = Player.query.filter(Player.tournament_id == self.tournament_id, Player.active==1)
       max_matches = db.session.query(func.max(Player.matches).filter(Player.active==1)).scalar()
       min_matches = db.session.query(func.min(Player.matches).filter(Player.active==1)).scalar()
       this_match_players = [] #list of Players
       # Turn the list of competitors into a dict of competitors grouped by number of matches played
       by_matches = {} #dict of Players
       for elem in lobby:
           try:
               by_matches[elem.matches].append(elem)
           except KeyError:
               by_matches[elem.matches] = [elem]

       #Starting with the list of players who have played the fewest matches, shuffle the list of 
       #players at a given match count, take the first 2*self.team_size (aka enough to make a match)
       #then keep going if we don't have a full match yet
       for i in range(min_matches, max_matches + 1):
           if(len(this_match_players) < 2*self.team_size):
               random.shuffle(by_matches[i])
               this_match_players.extend(by_matches[i][0:2*self.team_size - len(this_match_players)])

       #Shuffle our list of players again and return it. The caller will use the first team_size elements as red team,
       #and the remainder as blue team.

       random.shuffle(this_match_players)
       return this_match_players #returns a list of Players

    def create_match(self):
        if(Player.query.filter(Player.tournament_id==self.tournament_id,Player.active==1).count() < self.team_size*2):
            #TODO throw some exception or smth
            return
        this_match_players = self.pick_players_from_lobby() #Players, shuffled.
        red_team_str = ','.join([str(p.character_id) for p in this_match_players[0:self.team_size]])
        blue_team_str = ','.join([str(p.character_id) for p in this_match_players[self.team_size:self.team_size*2]])
        match = Match(tournament_id=self.tournament_id, red_team_name='red', red_team_members=red_team_str, blue_team_name='blue', blue_team_members = blue_team_str)
        self.current_match = match
        db.session.merge(match)
        db.session.merge(self)
        db.session.commit()


    def resolve_match(self, winning_team_name):
        match = self.current_match
        blue_team_wins = self.current_match.blue_team_name == winning_team_name
        red_team_wins = self.current_match.red_team_name == winning_team_name
        if(blue_team_wins == red_team_wins):
            raise Exception('BadWinningTeamName',winning_team_name)

        for character_id in self.current_match.get_red_players():
           comp = Player.query.filter(Player.character_id == character_id and Player.tournament_id == self.tournament_id).first()
           comp.matches = comp.matches + 1
           if red_team_wins:
               comp.wins = comp.wins + 1
           db.session.merge(comp)
           
        for character_id in self.current_match.get_blue_players():
           comp = Player.query.filter(Player.character_id == character_id and Player.tournament_id == self.tournament_id).first()
           if blue_team_wins:
               comp.wins = comp.wins + 1
           comp.matches = comp.matches + 1
           db.session.merge(comp)

        self.current_match = None
        db.session.merge(self)
        db.session.commit()


class User(db.Model, UserMixin):
    # our ID is the character ID from EVE API
    character_id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=False
    )
    character_owner_hash = db.Column(db.String(255))

    # SSO Token stuff
    access_token = db.Column(db.String(4096))
    access_token_expires = db.Column(db.DateTime())
    refresh_token = db.Column(db.String(100))

    def get_id(self):
        """ Required for flask-login """
        return self.character_id

    def get_sso_data(self):
        """ Little "helper" function to get formated data for esipy security
        """
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_in': (
                self.access_token_expires - datetime.utcnow()
            ).total_seconds()
        }

    def update_token(self, token_response):
        """ helper function to update token data from SSO response """
        self.access_token = token_response['access_token']
        self.access_token_expires = datetime.fromtimestamp(
            time.time() + token_response['expires_in'],
        )
        if 'refresh_token' in token_response:
            self.refresh_token = token_response['refresh_token']


class Character(db.Model):
    character_id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=False
    )
    character_name = db.Column(db.String(200))

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def get_current_tournaments():
    return(Tournament.db.Query.all())

# -----------------------------------------------------------------------
# Flask Login requirements
# -----------------------------------------------------------------------
@login_manager.user_loader
def load_user(character_id):
    """ Required user loader for Flask-Login """
    return User.query.get(character_id)


# -----------------------------------------------------------------------
# ESIPY Init
# -----------------------------------------------------------------------
# create the app
esiapp = EsiApp().get_latest_swagger

# init the security object
esisecurity = EsiSecurity(
    redirect_uri=config.ESI_CALLBACK,
    client_id=config.ESI_CLIENT_ID,
    secret_key=config.ESI_SECRET_KEY,
    headers={'User-Agent': config.ESI_USER_AGENT}
)

# init the client
esiclient = EsiClient(
    security=esisecurity,
    cache=None,
    headers={'User-Agent': config.ESI_USER_AGENT}
)


# -----------------------------------------------------------------------
# Individual Tournament Route
# Just doing soloQ for now
# -----------------------------------------------------------------------
@app.route('/tournament/<int:tid>')
def get_tournament(tid):
    tournament = Tournament.query.filter_by('tournament_id' == tid).first()

# -----------------------------------------------------------------------
# Login / Logout Routes
# -----------------------------------------------------------------------
def generate_token():
    """Generates a non-guessable OAuth token"""
    chars = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    rand = random.SystemRandom()
    random_string = ''.join(rand.choice(chars) for _ in range(40))
    return hmac.new(
        config.SECRET_KEY.encode('utf-8'),
        random_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


@app.route('/sso/login')
def login():
    """ this redirects the user to the EVE SSO login """
    token = generate_token()
    session['token'] = token
    return redirect(esisecurity.get_auth_uri(
        state=token,
        scopes=['publicData']
    ))


@app.route('/sso/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route('/sso/callback')
def callback():
    """ This is where the user comes after he logged in SSO """
    # get the code from the login process
    code = request.args.get('code')
    token = request.args.get('state')

    # compare the state with the saved token for CSRF check
    sess_token = session.pop('token', None)
    if sess_token is None or token is None or token != sess_token:
        return 'Login EVE Online SSO failed: Session Token Mismatch', 403

    # now we try to get tokens
    try:
        auth_response = esisecurity.auth(code)
    except APIException as e:
        return 'Login EVE Online SSO failed: %s' % e, 403

    # we get the character informations
    cdata = esisecurity.verify()

    # if the user is already authed, we log him out
    if current_user.is_authenticated:
        logout_user()

    # Check to see if we already have a record for this character
    try:
        character = Character.query.filter(Character.character_id == cdata['sub'].split(':')[2],
        ).one()
    except NoResultFound:
        character = Character()
        character.character_id = cdata['sub'].split(':')[2]

    # now check to see if we have a record for this user
    # actually we'd have to also check with character_owner_hash, to be
    # sure the owner is still the same, but that's an example only...
    try:
        user = User.query.filter(
            User.character_id == cdata['sub'].split(':')[2],
        ).one()

    except NoResultFound:
        user = User()
        user.character_id = cdata['sub'].split(':')[2]

    user.character_owner_hash = cdata['owner']
    character.character_name = cdata['name']
    user.update_token(auth_response)

    # now the user is ready, so update/create it and character if needed and log the user
    try:
        db.session.merge(user)
        db.session.merge(character)
        db.session.commit()

        login_user(user)
        session.permanent = True

    except:
        logger.exception("Cannot login the user - uid: %d" % user.character_id)
        db.session.rollback()
        logout_user()

    return redirect(url_for("index"))


# -----------------------------------------------------------------------
# Index Routes
# -----------------------------------------------------------------------
@app.route('/')
def index():

    if current_user.is_authenticated:
        # give the token data to esisecurity, it will check alone
        # if the access token need some update
        esisecurity.update_token(current_user.get_sso_data())
        current_tournaments = get_current_tournaments()
    else:
        current_tournaments = []

    return render_template('base.html', current_tournaments=current_tournaments)

@app.route('/debug')
def debug():
    test = SoloQueue.query.all()[0]
    test.create_match()
    test.resolve_match('red')
    test.leave_lobby(18)
    test.create_match()
    test.resolve_match('blue')
    test.join_lobby(18)
    raise Exception("EverythingWorked","Sounds fake...")

if __name__ == '__main__':
    app.run(port=config.PORT, host=config.HOST)
