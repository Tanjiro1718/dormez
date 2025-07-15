from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-change-in-production")

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'mysql+mysqlconnector://root:096161@localhost:3309/dorm'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(10), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    rent_price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    is_available = db.Column(db.Boolean, default=True)
    landlord_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    boarder_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Database creation function
def create_database_if_missing():
    """Creates database if it doesn't exist"""
    try:
        uri = app.config['SQLALCHEMY_DATABASE_URI']
        db_name = uri.split('/')[-1]
        base_uri = uri.rsplit('/', 1)[0]
        
        temp_engine = create_engine(base_uri)
        with temp_engine.connect() as conn:
            conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {db_name}"))
            conn.commit()
    except OperationalError as e:
        app.logger.error(f"Database creation failed: {str(e)}")

# Authentication decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login first', 'danger')
                return redirect(url_for('login'))
            if session.get('role') != role:
                flash('Access denied', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register')
def register_choice():
    return render_template('register_choice.html')

@app.route('/register/boarder', methods=['GET', 'POST'])
def register_boarder():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Validation
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register_boarder'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register_boarder'))
        
        # Create new boarder
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            email=email,
            role='boarder',
            status='pending'
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register_boarder.html')

@app.route('/register/landlord', methods=['GET', 'POST'])
def dlord():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Validation
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register_landlord'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register_landlord'))
        
        # Create new landlord
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            email=email,
            role='landlord',
            status='pending'
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register_landlord.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            if user.status != 'approved':
                flash('Your account is pending approval', 'warning')
                return redirect(url_for('login'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    print("🧭 Redirecting to dashboard:", session.get('role'))
    role = session.get('role')
    if role == 'boarder':
        return redirect(url_for('boarder_dashboard'))
    elif role == 'landlord':
        return redirect(url_for('landlord_dashboard'))
    elif role == 'owner':
        return redirect(url_for('owner_dashboard'))
    else:
        flash('Unknown user role', 'danger')
        return redirect(url_for('logout'))

@app.route('/boarder/dashboard')
@role_required('boarder')
def boarder_dashboard():
    # Get available rooms
    available_rooms = Room.query.filter_by(is_available=True).all()
    
    # Get user's current bookings
    user_bookings = db.session.query(Booking, Room).join(Room).filter(
        Booking.boarder_id == session['user_id'],
        Booking.status == 'active'
    ).all()
    
    return render_template('boarder_dashboard.html', 
                         available_rooms=available_rooms,
                         user_bookings=user_bookings)

@app.route('/landlord/dashboard')
@role_required('landlord')
def landlord_dashboard():
    my_rooms = Room.query.filter_by(landlord_id=session['user_id']).all()
    my_bookings = db.session.query(Booking, Room, User).join(Room).join(
        User, Booking.boarder_id == User.id
    ).filter(Room.landlord_id == session['user_id']).all()
    
    # ✅ Get landlord user
    user = User.query.get(session['user_id'])
    
    # ✅ PASS current_user to template
    return render_template(
        'landlord_dashboard.html',
        my_rooms=my_rooms,
        my_bookings=my_bookings,
        current_user=user
    )

@app.route('/owner/dashboard')
@role_required('owner')
def owner_dashboard():
    try:
        print("✅ Inside owner_dashboard")
        pending_users = User.query.filter_by(status='pending').all()
        all_rooms = Room.query.all()
        all_bookings = db.session.query(Booking, Room, User).\
        join(Room, Booking.room_id == Room.id).\
        join(User, Booking.boarder_id == User.id).all()
        stats = {
            'total_users': User.query.count(),
            'total_rooms': Room.query.count(),
            'active_bookings': Booking.query.filter_by(status='active').count(),
            'pending_approvals': User.query.filter_by(status='pending').count()
        }
        print("✅ All queries successful")
        return render_template('owner_dashboard.html',
                               pending_users=pending_users,
                               all_rooms=all_rooms,
                               all_bookings=all_bookings,
                               stats=stats)
    except Exception as e:
        import traceback
        print("🔥 Error in owner_dashboard:", e)
        traceback.print_exc()
        return "Something went wrong in owner dashboard", 500


@app.route('/approve_user/<int:user_id>')
@role_required('owner')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = 'approved'
    db.session.commit()
    flash(f'User {user.username} has been approved', 'success')
    return redirect(url_for('owner_dashboard'))

@app.route('/reject_user/<int:user_id>')
@role_required('owner')
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = 'rejected'
    db.session.commit()
    flash(f'User {user.username} has been rejected', 'warning')
    return redirect(url_for('owner_dashboard'))

@app.route('/add_room', methods=['GET', 'POST'])
@role_required('landlord')
def add_room():
    if request.method == 'POST':
        room_number = request.form['room_number']
        capacity = int(request.form['capacity'])
        rent_price = float(request.form['rent_price'])
        description = request.form['description']
        
        # Check if room number already exists
        if Room.query.filter_by(room_number=room_number).first():
            flash('Room number already exists', 'danger')
            return redirect(url_for('add_room'))
        
        new_room = Room(
            room_number=room_number,
            capacity=capacity,
            rent_price=rent_price,
            description=description,
            landlord_id=session['user_id']
        )
        
        db.session.add(new_room)
        db.session.commit()
        
        flash('Room added successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))
    
    return render_template('add_room.html')

@app.route('/book_room/<int:room_id>')
@role_required('boarder')
def book_room(room_id):
    room = Room.query.get_or_404(room_id)
    
    if not room.is_available:
        flash('Room is not available', 'danger')
        return redirect(url_for('boarder_dashboard'))
    
    # Create booking
    new_booking = Booking(
        room_id=room_id,
        boarder_id=session['user_id'],
        start_date=datetime.utcnow()
    )
    
    # Mark room as unavailable
    room.is_available = False
    
    db.session.add(new_booking)
    db.session.commit()
    
    flash(f'Room {room.room_number} booked successfully!', 'success')
    return redirect(url_for('boarder_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('home'))

# Initialize database
def init_db():
    with app.app_context():
        create_database_if_missing()
        db.create_all()
        
        # Create default admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                email='admin@dormitory.com',
                role='owner',
                status='approved'
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: admin/admin123")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)