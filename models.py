from flask_sqlalchemy import SQLAlchemy
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from zoneinfo import ZoneInfo
import pytz
db = SQLAlchemy(app)
## db models

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, nullable=False)
    passhash = db.Column(db.String(512), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    is_admin = db.Column(db.Boolean, nullable = False, default = False)
    
    #relationship
    parking_lot = db.relationship('Parking_Lot', backref='owner', lazy=True)

    
    @property
    def password(self):
        raise AttributeError('Password is not readable')
    
    @password.setter
    def password(self, password):
        self.passhash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.passhash, password)
    
class Parking_Lot(db.Model):
    __tablename__ = 'parking_lot'
    
    id = db.Column(db.Integer, primary_key=True)
    prime_location_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(255), nullable=False)
    pincode = db.Column(db.String(10), nullable=False)
    maximum_number_of_spots = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
   
    def seed_spots(self):
        
        if not self.id:
            raise ValueError("Parking Lot must be committed before seeding spots.")

        existing_spots = Parking_Spot.query.filter_by(lot_id=self.id).count()
        spots_to_create = self.maximum_number_of_spots - existing_spots
        
        for _ in range(spots_to_create):
            spot = Parking_Spot(status='A', lot_id=self.id)
            db.session.add(spot)
    
    #relationship
    parking_spot = db.relationship('Parking_Spot', back_populates='parking_lot', lazy=True)
        
    @property
    def occupied(self):
        return sum(1 for spot in self.parking_spot if spot.status == 'O')

    @property
    def available(self):
        return sum(1 for spot in self.parking_spot if spot.status == 'A')
    
    
    

class Parking_Spot(db.Model):
    __tablename__ = 'parking_spot'

    id = db.Column(db.Integer, primary_key=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    status = db.Column(db.String(1), nullable=False, default='A')  ## 'A'-Available/'O'-Occupied
    
    #relationship
    parking_lot = db.relationship('Parking_Lot', back_populates='parking_spot', lazy=True)
    
    def get_active_reservation_count(self):
        return sum(1 for r in self.lot if r.leaving_timestamp is None)

class Reserve_Parking_Spot(db.Model):
    _tablename_ = 'reserve_parking_spot'

    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parking_timestamp = db.Column(db.DateTime, nullable=False)
    leaving_timestamp = db.Column(db.DateTime, nullable=True)
    parking_cost = db.Column(db.Float)
    vehicle_no = db.Column(db.String(20), nullable=False)

    # Relationships
    parking_lot = db.relationship('Parking_Lot')
    parking_spot = db.relationship('Parking_Spot', backref='reserve_parking_spot', lazy=True)
    user = db.relationship('User', backref='reserve_parking_spot', lazy=True)
    
#creating db if not exist
with app.app_context():
    db.create_all()
    #Generating new admin if not exist
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(email='admin@geniusparking.com', password='admin', name='admin', address='admin office', pincode='000000', is_admin=True)
        db.session.add(admin)
        db.session.commit()