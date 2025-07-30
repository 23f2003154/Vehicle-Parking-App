from functools import wraps 

from datetime import datetime

from flask import Flask, render_template, redirect, url_for, flash, request, session

from models import db, User, Parking_Lot, Parking_Spot, Reserve_Parking_Spot

from sqlalchemy import func

from sqlalchemy import case

from flask import jsonify

from decimal import Decimal

from datetime import datetime

from zoneinfo import ZoneInfo

import pytz

from app import app

def auth_checker(func):
    @wraps(func)
    def core(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'danger')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return core

def auth_admin(func):
    @wraps(func)
    def core(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first!', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not allowed to view this page!', 'danger')
            return redirect(url_for('profile'))
        return func(*args, **kwargs)
    return core

@app.route('/')
@auth_checker
def index():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)

@app.route('/admin_dashboard')
@auth_admin
def admin_dashboard():
    if not session.get('user_id') or not User.query.get(session['user_id']).is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('login'))

    parking_lot = Parking_Lot.query.all() 
    return render_template('admin_dashboard.html', user=User.query.get(session['user_id']), parking_lot=parking_lot)

@app.route('/profile')
@auth_checker
def profile():
        return render_template('profile.html', user=User.query.get(session['user_id']))

@app.route('/profile', methods=['POST'])
@auth_checker
def profile_post():
    user = User.query.get(session['user_id'])
    email= request.form.get('email')
    fullname = request.form.get('fullname')
    address = request.form.get('address')
    pincode = request.form.get('pincode')
    password = request.form.get('password')
    npassword = request.form.get('npassword')
    if not all([email, fullname, address, pincode, password, npassword]):
        flash('All fields are required', 'danger')
        return redirect(url_for('profile'))
    if not user.check_password(npassword):
        flash('The password is incorrect', 'danger')
        return redirect(url_for('profile'))
    if User.query.filter_by(email=email).first() and email != user.email:
        flash('Username already exists. Please choose a different username', 'danger')
        return redirect(url_for('profile'))
    user.email = email
    user.name = fullname
    user.address = address
    user.pincode = pincode
    user.password = password
    db.session.commit()
    flash('Profile updated successfully', 'success')
    return redirect(url_for('login')) 

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    if email ==  '' or password == '' :
        flash('Username or Password cannot be empty', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Username not found!', 'danger')
        return redirect(url_for('login'))
    if not user.check_password(password):
        flash('Password is incorrect!' , 'danger')
        return redirect(url_for('login'))
    #login worked
    session['user_id'] = user.id
    if user.is_admin:
        flash('Welcome admin, redirecting to admin dashboard.', 'info')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('You have successfully logged in', 'success')
    return redirect(url_for('profile'))


@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    password = request.form.get('password')
    address = request.form.get('address')
    pincode = request.form.get('pincode')
    if email == '' or password == '' or not address or not pincode:
        flash('All fields are required' , 'danger')
        return redirect(url_for('register'))
    if User.query.filter_by(email=email).first():
        flash('Username already exists. Please chose a different username' , 'danger')
        return redirect(url_for('register'))
    user = User(email=email, password=password, name=fullname, address=address, pincode=pincode)
    db.session.add(user)
    db.session.commit()
    flash('Registration Successful', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/user_dashboard', methods=['GET', 'POST'])
@auth_checker
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    search_query = request.args.get('prime_location_name', '').strip()

    history = Reserve_Parking_Spot.query.filter_by(user_id=user_id).order_by(
        Reserve_Parking_Spot.parking_timestamp.desc()
    ).all()

    if search_query:
        parking_lot = Parking_Lot.query.filter(
            (Parking_Lot.prime_location_name.ilike(f"%{search_query}%")) |
            (Parking_Lot.pincode.ilike(f"%{search_query}%"))
        ).all()
    else:
        parking_lot = Parking_Lot.query.all()
        

    user = User.query.get(user_id)

    return render_template(
        'user_dashboard.html',
        user=user,
        history=history,
        parking_lot=parking_lot,
        search_query=search_query
    )

@app.route('/admin_dashboard/add_lot', methods=['GET', 'POST'])
@auth_admin
def add_lot():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'GET':
        return render_template('parking_lot.html', user=user)

    prime_location_name = request.form.get('prime_location_name')
    price = request.form.get('price')
    address = request.form.get('address')
    pincode = request.form.get('pincode')
    maximum_number_of_spots = request.form.get('maximum_number_of_spots')

    if not all([prime_location_name, price, address, pincode, maximum_number_of_spots]):
        flash("Please fill all the fields", "danger")
        return render_template('parking_lot.html', user=user)

    new_lot = Parking_Lot(
        prime_location_name=prime_location_name,
        price=price,
        address=address,
        pincode=pincode,
        maximum_number_of_spots=maximum_number_of_spots,
        user_id=user.id
    )
    db.session.add(new_lot)
    db.session.commit()
    new_lot.seed_spots()
    db.session.commit()

    flash("Parking Lot created successfully!", "success")
    return redirect(url_for('admin_dashboard'))



@app.route('/admin_dashboard/users')
@auth_admin
def registered_users():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('profile'))

    users = User.query.filter_by(is_admin=False).all()

    return render_template('users.html', user=user, users=users)


@app.route('/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
@auth_admin
def edit_lot(lot_id):
    if not session.get('user_id'):
        flash('Login required', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('profile'))
    
    lot = Parking_Lot.query.get_or_404(lot_id)
    if request.method == 'POST':
        lot.prime_location_name = request.form['prime_location_name']
        lot.address = request.form['address']
        lot.pincode = request.form['pincode']
        lot.price = request.form['price']
        lot.maximum_number_of_spots = int(request.form['maximum_number_of_spots'])
        db.session.commit()
        
        lot.seed_spots()
        db.session.commit()
        
        flash('Parking lot updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_lot.html', lot=lot,  user=User.query.get(session['user_id']))

@app.route('/delete_lot/<int:lot_id>', methods=['GET', 'POST'])
@auth_admin
def delete_lot(lot_id):
    if not session.get('user_id'):
        flash('Login required', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('profile'))

    lot = Parking_Lot.query.get_or_404(lot_id)

    # Checking the occupied spots
    occupied_spots = Parking_Spot.query.filter_by(lot_id=lot.id, status='O').count()
    if occupied_spots > 0:
        flash("Cannot delete lot — one or more parking spots are currently occupied.", "danger")
        return redirect(url_for('admin_dashboard', user=user))

    Parking_Spot.query.filter_by(lot_id=lot.id).delete()
    db.session.delete(lot)
    db.session.commit()

    flash('Parking lot deleted successfully', 'success')
    return redirect(url_for('admin_dashboard', user=user))

@app.route('/spot/<int:spot_id>', methods=['GET', 'POST'])
@auth_admin
def view_or_delete_spot(spot_id):
    if not session.get('user_id'):
        flash('Login required', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('user_dashboard'))

    spot = Parking_Spot.query.get_or_404(spot_id)
    lot = Parking_Lot.query.get_or_404(spot.lot_id)
    
    has_reservations = Reserve_Parking_Spot.query.filter_by(spot_id=spot.id).count() > 0

    if request.method == 'POST':
        if spot.status == 'A' and not has_reservations:
            db.session.delete(spot)
            db.session.commit()
            flash("Parking spot deleted successfully", "success")
            return redirect(url_for('admin_dashboard', user=User.query.get(session['user_id'])))
        else:
            flash("Cannot delete an occupied spot.", "danger")
            return redirect(url_for('view_or_delete_spot', spot_id=spot_id))

    return render_template('view_or_delete_spot.html', spot=spot, lot=lot, user=User.query.get(session['user_id']))

@app.route('/occupied_spot/<int:spot_id>')
@auth_admin
def occupied_spot_details(spot_id):
    if not session.get('user_id'):
        flash('Login required', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('user_dashboard'))

    spot = Parking_Spot.query.get_or_404(spot_id)


    if spot.status != 'O':
        flash('This parking spot is not currently occupied.', 'warning')
        return redirect(url_for('view_or_delete_spot', spot_id=spot_id))


    reservation = Reserve_Parking_Spot.query.filter_by(spot_id=spot.id).order_by(Reserve_Parking_Spot.parking_timestamp.desc()).first()

    if not reservation:
        flash('No active reservation found for this spot.', 'danger')
        return redirect(url_for('view_or_delete_spot', spot_id=spot_id))

    # Calculate cost
    time_parked = datetime.utcnow() - reservation.parking_timestamp
    hours = max(1, int(time_parked.total_seconds() // 3600))  
    cost = hours * spot.parking_lot.price

    return render_template('occupied_spot_details.html',
                           spot=spot,
                           reservation=reservation,
                           cost=cost,
                           user=user)



@app.route('/admin_dashboard/search', methods=['GET','POST'])
@auth_admin
def search():
    if not session.get('user_id'):
        flash('Login required', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('profile'))

    filter_by = request.args.get('filter')
    query = request.args.get('query')

    lot = []

    if filter_by == 'user_id' and query:
        user = User.query.filter_by(id=query).first()
        lot = user.parking_lot if user else []
    elif filter_by == 'location' and query:
        lot = Parking_Lot.query.filter(Parking_Lot.prime_location_name.ilike(f"%{query}%")).all()
    elif filter_by == 'lot_id' and query:
        lot_obj = Parking_Lot.query.get(query)
        lot = [lot_obj] if lot_obj else []

    return render_template("search.html", lot=lot, location_query=query,  user=User.query.get(session['user_id']))

@app.route('/admin_dashboard/summary')
@auth_admin     
def summary():
    # Revenue chart data
    revenue_info = db.session.query(
        Parking_Lot.prime_location_name,
        func.sum(Reserve_Parking_Spot.parking_cost)
    ).select_from(Parking_Lot) \
    .join(Parking_Spot, Parking_Spot.lot_id == Parking_Lot.id) \
    .join(Reserve_Parking_Spot, Reserve_Parking_Spot.spot_id == Parking_Spot.id) \
    .group_by(Parking_Lot.prime_location_name).all()

    revenue_labels = [location for location, _ in revenue_info]
    revenue_values = [float(revenue or 0) for _, revenue in revenue_info]

    # Occupied vs Available chart data
    status_info = db.session.query(
        Parking_Lot.prime_location_name,
        func.sum(case((Parking_Spot.status == 'A', 1), else_=0)).label('available'),
        func.sum(case((Parking_Spot.status == 'O', 1), else_=0)).label('occupied')
    ).select_from(Parking_Lot) \
    .join(Parking_Spot, Parking_Spot.lot_id == Parking_Lot.id) \
    .group_by(Parking_Lot.prime_location_name).all()

    status_labels = [lot for lot, _, _ in status_info]
    available_values = [a for _, a, _ in status_info]
    occupied_values = [o for _, _, o in status_info]

    return render_template(
        'summary.html',
        data=revenue_info,
        labels=revenue_labels,
        values=revenue_values,
        status_labels=status_labels,
        available_values=available_values,
        occupied_values=occupied_values,
        user = User.query.get(session['user_id'])
    )

@app.route('/user_summary')
@auth_checker
def user_summary():
    user_id = session.get('user_id')
    reserved_spots = Reserve_Parking_Spot.query.filter_by(user_id=user_id).count()
    total_spots = Parking_Spot.query.count()
    occupied_spots = Parking_Spot.query.filter_by(status='O').count()
    available_spots = total_spots - occupied_spots

    return render_template('user_summary.html',
                           available=available_spots,
                           occupied=occupied_spots,
                           reserved=reserved_spots,
                          user=User.query.get(session['user_id']))



@app.route('/reserve_parking/<int:lot_id>', methods=['GET'])
@auth_checker
def reserve_parking(lot_id):
    lot = Parking_Lot.query.get_or_404(lot_id)
    available_spots = Parking_Spot.query.filter_by(lot_id=lot.id, status='A').all()

    return render_template('reserve_parking.html', lot=lot, available_spots=available_spots, user = User.query.get(session['user_id']))



@app.route('/reserve_spot/<int:spot_id>', methods=['GET', 'POST'])
@auth_checker
def reserve_spot(spot_id):
    spot = Parking_Spot.query.get_or_404(spot_id)

    if spot.status != 'A':
        flash('This spot is already booked.', 'danger')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        vehicle_number = request.form['vehicle_number']
        user_id = session['user_id']

        reservation = Reserve_Parking_Spot(
            user_id=user_id,
            lot_id=spot.lot_id,
            spot_id=spot.id,
            parking_timestamp=datetime.utcnow(),
            vehicle_no=vehicle_number
        )
        spot.status = 'O'
        db.session.add(reservation)
        db.session.commit()

        flash('Parking spot reserved successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('confirm_booking.html', spot=spot, user = User.query.get(session['user_id']))

@app.route('/release/<int:reservation_id>', methods=['GET', 'POST'])
@auth_checker
def release_parking(reservation_id):
    reservation = Reserve_Parking_Spot.query.get_or_404(reservation_id)
    lot = Parking_Lot.query.get_or_404(reservation.lot_id)
    spot = Parking_Spot.query.get_or_404(reservation.spot_id)

    if request.method == 'POST':
        reservation.leaving_timestamp = datetime.utcnow()

        # Calculating parking duration in hours
        delta = reservation.leaving_timestamp - reservation.parking_timestamp
        hours = max(1, int(delta.total_seconds() // 3600))
        reservation.parking_cost = round(hours * lot.price, 2)

        # Mark Available
        spot.status = 'A'

        db.session.commit()
        return redirect(url_for('user_dashboard'))

    now = datetime.utcnow()
    delta = now - reservation.parking_timestamp
    hours = max(1, int(delta.total_seconds() // 3600))
    estimated_cost = round(hours * lot.price, 2)

    return render_template(
        'spot_release.html',
        reservation=reservation,
        lot=lot,
        now=now,
        estimated_cost=estimated_cost,
        user = User.query.get(session['user_id'])
    )







