from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import traceback
import logging
import requests
import joblib
from PIL import Image
import numpy as np
from flask_mail import Mail, Message

mysql://root:xFJUcsfekMwYBgasPmBWCpPdIVHgZTps@yamanote.proxy.rlwy.net:12705/railway

clf = joblib.load('photo_verification_model.pkl')


def extract_features(image_path):
    img = Image.open(image_path).resize((64, 64)).convert('L')
    return np.array(img).flatten().reshape(1, -1)


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET",
                                "your-secret-key-change-in-production")

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'mysql+mysqlconnector://root:xFJUcsfekMwYBgasPmBWCpPdIVHgZTps@yamanote.proxy.rlwy.net:12705/railway'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'tristhanilarde1718@gmail.com'
app.config['MAIL_USERNAME'] = 'tristhanilarde1718@gmail.com'
app.config['MAIL_PASSWORD'] = 'yrlq qpbd bmex beeb'

mail = Mail(app)

try:
    db = SQLAlchemy(app)
    logger.info("✅ SQLAlchemy initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize SQLAlchemy: {e}")
    raise


# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    photo = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reset_code = db.Column(db.String(10), nullable=True)
    profile_photo = db.Column(db.String(255), nullable=True)


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
    photo = db.Column(db.String(255))


class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    boarder_id = db.Column(db.Integer,
                           db.ForeignKey('users.id'),
                           nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Database creation function
def create_database_if_missing():
    """Creates database if it doesn't exist"""
    try:
        logger.info("🔄 Attempting to create database if missing...")
        uri = app.config['SQLALCHEMY_DATABASE_URI']
        db_name = uri.split('/')[-1]
        base_uri = uri.rsplit('/', 1)[0]

        temp_engine = create_engine(base_uri)
        with temp_engine.connect() as conn:
            conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {db_name}"))
            conn.commit()
        logger.info("✅ Database creation check completed")
    except OperationalError as e:
        logger.error(f"❌ Database creation failed: {str(e)}")
        raise


# Test database connection
def test_db_connection():
    """Test database connection"""
    try:
        logger.info("🔄 Testing database connection...")
        with app.app_context():
            with db.engine.connect() as conn:
                conn.execute(text('SELECT 1'))
        logger.info("✅ Database connection successful")
        return True
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False


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


# Error handlers
@app.errorhandler(500)
def internal_error(error):
    logger.error(f"❌ Internal Server Error: {error}")
    db.session.rollback()
    return "Internal Server Error - Check console for details", 500


@app.errorhandler(404)
def not_found_error(error):
    return "Page not found", 404


# Routes
@app.route('/')
def home():
    try:
        logger.info("🏠 Home route accessed")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"❌ Error in home route: {e}")
        traceback.print_exc()
        return f"Error in home route: {str(e)}", 500


@app.route('/register')
def register_choice():
    try:
        return render_template('register_choice.html')
    except Exception as e:
        logger.error(f"❌ Error in register_choice: {e}")
        return f"Template error: {str(e)}", 500


@app.route('/register/boarder', methods=['GET', 'POST'])
def register_boarder():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']

            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('register_boarder'))

            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect(url_for('register_boarder'))

            hashed_password = generate_password_hash(password)
            new_user = User(username=username,
                            password=hashed_password,
                            email=email,
                            role='boarder',
                            status='pending')

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please wait for admin approval.',
                  'success')
            return redirect(url_for('login'))

        return render_template('register_boarder.html')
    except Exception as e:
        logger.error(f"❌ Error in register_boarder: {e}")
        traceback.print_exc()
        db.session.rollback()
        return f"Registration error: {str(e)}", 500


@app.route('/register/landlord', methods=['GET', 'POST'])
def register_landlord():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            file = request.files['photo']

            recaptcha_response = request.form.get('g-recaptcha-response')
            secret = '6Le7fXkrAAAAAItVOtubBGjinYKEEi9YLLHfsMKR'
            payload = {'secret': secret, 'response': recaptcha_response}
            r = requests.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data=payload)
            result = r.json()
            if not result.get('success'):
                flash('Invalid reCAPTCHA. Please try again.', 'danger')
                return redirect(url_for('register_landlord'))

            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('register_landlord'))

            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect(url_for('register_landlord'))

            if file and file.filename != '':
                filename = f"{username}_{file.filename}"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)

                try:
                    features = extract_features(file_path)
                except Exception as e:
                    logger.error(f"❌ Image processing error: {e}")
                    flash(
                        'Invalid or corrupted image file. Please upload a valid photo.',
                        'danger')
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    return redirect(url_for('register_landlord'))

                prediction = clf.predict(features)[0]
                if prediction == 1:
                    flash(
                        'Photo verification failed. Please upload a real photo.',
                        'danger')
                    return redirect(url_for('register_landlord'))

            # Create new landlord
            hashed_password = generate_password_hash(password)
            new_user = User(username=username,
                            password=hashed_password,
                            email=email,
                            role='landlord',
                            status='pending',
                            photo=filename)

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please wait for admin approval.',
                  'success')
            return redirect(url_for('login'))

        return render_template('register_landlord.html')
    except Exception as e:
        logger.error(f"❌ Error in register_landlord: {e}")
        traceback.print_exc()
        db.session.rollback()
        return f"Registration error: {str(e)}", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
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
    except Exception as e:
        logger.error(f"❌ Error in login: {e}")
        traceback.print_exc()
        return f"Login error: {str(e)}", 500


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        user = User.query.filter_by(username=username, email=email).first()

        if user:
            import random
            code = str(random.randint(100000, 999999))
            user.reset_code = code
            db.session.commit()

            msg = Message('Password Reset Code', recipients=[email])
            msg.body = f"Hi {username}, your reset code is: {code}"
            try:
                mail.send(msg)
                flash('✅ A code has been sent to your email.', 'success')
                return redirect(url_for('verify_reset_code', user_id=user.id))
            except Exception as e:
                print(f"Email error: {e}")
                flash('❌ Email sending failed. Please check email config.',
                      'danger')
        else:
            flash('⚠️ Username and email do not match.', 'warning')

    return render_template('forgot_password_dashboard.html')


@app.route('/verify_reset_code/<int:user_id>', methods=['GET', 'POST'])
def verify_reset_code(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('⚠️ User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_code = request.form['code']
        if entered_code == user.reset_code:
            flash('✅ Code verified. You can now reset your password.',
                  'success')
            return redirect(url_for('reset_password', user_id=user.id))
        else:
            flash('❌ Invalid code.', 'danger')

    return render_template('verify_reset_code.html', user=user)


@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('⚠️ User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if new_password != confirm_password:
            flash('⚠️ Passwords do not match.', 'danger')
            return redirect(request.url)

        # Save new password
        user.password = generate_password_hash(new_password)
        user.reset_code = None
        db.session.commit()
        flash('✅ Password reset successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', user=user)


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        logger.info(
            f"🧭 Dashboard accessed by user: {session.get('username')} with role: {session.get('role')}"
        )
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
    except Exception as e:
        logger.error(f"❌ Error in dashboard: {e}")
        traceback.print_exc()
        return f"Dashboard error: {str(e)}", 500


@app.route('/boarder/dashboard')
@role_required('boarder')
def boarder_dashboard():
    try:
        available_rooms = Room.query.filter_by(is_available=True).all()
        user_bookings = db.session.query(Booking, Room).join(Room).filter(
            Booking.boarder_id == session['user_id'],
            Booking.status == 'active').all()
        user = db.session.get(User, session['user_id'])

        return render_template(
            'boarder_dashboard.html',
            available_rooms=available_rooms,
            user_bookings=user_bookings,
            current_user=user  # 💥 Pass here
        )
    except Exception as e:
        logger.error(f"❌ Error in boarder_dashboard: {e}")
        traceback.print_exc()
        return f"Boarder dashboard error: {str(e)}", 500


UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/boarder/update_profile_photo', methods=['GET', 'POST'])
@role_required('boarder')
def update_profile_photo_boarder():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename != '':
                from werkzeug.utils import secure_filename
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                user.profile_photo = filename
                db.session.commit()
                flash('✅ Profile photo updated successfully!', 'success')
                return redirect(url_for('boarder_dashboard'))
    return render_template('update_profile_photo.html', user=user)


@app.route('/landlord/dashboard')
@role_required('landlord')
def landlord_dashboard():
    my_rooms = Room.query.filter_by(landlord_id=session['user_id']).all()

    my_bookings = db.session.query(Booking, Room, User)\
        .select_from(Booking)\
        .join(Room, Booking.room_id == Room.id)\
        .join(User, Booking.boarder_id == User.id)\
        .filter(Room.landlord_id == session['user_id'])\
        .all()

    user = db.session.get(User, session['user_id'])

    return render_template('landlord_dashboard.html',
                           my_rooms=my_rooms,
                           my_bookings=my_bookings,
                           current_user=user)


@app.route('/delete_room/<int:room_id>', methods=['POST'])
@role_required('landlord')
def delete_room(room_id):
    try:
        room = Room.query.get_or_404(room_id)
        # Optional: Check if the current landlord is the owner
        if room.landlord_id != session['user_id']:
            flash("⚠️ You are not authorized to delete this room.", "danger")
            return redirect(url_for('landlord_dashboard'))

        # Delete bookings related to this room
        bookings = Booking.query.filter_by(room_id=room.id).all()
        for booking in bookings:
            db.session.delete(booking)

        # Delete room photo if needed
        if room.photo:
            photo_path = os.path.join(UPLOAD_FOLDER, room.photo)
            if os.path.exists(photo_path):
                os.remove(photo_path)

        db.session.delete(room)
        db.session.commit()
        flash("✅ Room deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Error deleting room: {e}", "danger")
    return redirect(url_for('landlord_dashboard'))


@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@role_required('boarder')
def cancel_booking(booking_id):
    try:
        booking = Booking.query.get_or_404(booking_id)

        # Check if the booking belongs to the current boarder
        if booking.boarder_id != session['user_id']:
            flash("⚠️ You are not authorized to cancel this booking.",
                  "danger")
            return redirect(url_for('boarder_dashboard'))

        # Set the room back to available
        room = Room.query.get(booking.room_id)
        room.is_available = True

        # Delete the booking
        db.session.delete(booking)
        db.session.commit()

        flash("✅ Booking cancelled successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"❌ Error cancelling booking: {e}", "danger")

    return redirect(url_for('boarder_dashboard'))


@app.route('/landlord/update_profile_photo', methods=['GET', 'POST'])
@role_required('landlord')
def update_profile_photo():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_photo = filename
                db.session.commit()
                flash('✅ Profile photo updated successfully!', 'success')
                return redirect(url_for('landlord_dashboard'))
    return render_template('update_profile_photo.html', user=user)


@app.route('/owner/dashboard')
@role_required('owner')
def owner_dashboard():
    try:
        logger.info("✅ Inside owner_dashboard")

        pending_users = User.query.filter_by(status='pending').all()
        all_users = User.query.all()

        all_rooms = Room.query.all()
        all_bookings = db.session.query(Booking, Room, User).\
            join(Room, Booking.room_id == Room.id).\
            join(User, Booking.boarder_id == User.id).all()

        stats = {
            'total_users': User.query.count(),
            'total_rooms': Room.query.count(),
            'active_bookings':
            Booking.query.filter_by(status='active').count(),
            'pending_approvals':
            User.query.filter_by(status='pending').count()
        }

        return render_template('owner_dashboard.html',
                               pending_users=pending_users,
                               all_users=all_users,
                               all_rooms=all_rooms,
                               all_bookings=all_bookings,
                               stats=stats)
    except Exception as e:
        logger.error(f"❌ Error in owner_dashboard: {e}")
        traceback.print_exc()
        return f"Owner dashboard error: {str(e)}", 500


@app.route('/owner/delete_user/<int:user_id>', methods=['POST'])
@role_required('owner')
def owner_delete_user(user_id):
    try:
        user = db.session.get(User, user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            flash('✅ User deleted successfully.', 'success')
        else:
            flash('⚠️ User not found.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('❌ Error deleting user.', 'danger')
        print(f"Error: {e}")

    return redirect(url_for('owner_dashboard'))


@app.route('/approve_user/<int:user_id>')
@role_required('owner')
def approve_user(user_id):
    try:
        user = db.session.get(User, user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('owner_dashboard'))

        user.status = 'approved'
        db.session.commit()

        # Send email
        msg = Message('Your DormEZ Account is Approved',
                      recipients=[user.email])
        msg.body = f"Hello {user.username},\n\nYour DormEZ account has been approved. You can now log in and use the system.\n\nThank you!"
        mail.send(msg)

        flash(f'User {user.username} approved and notified.', 'success')
        return redirect(url_for('owner_dashboard'))
    except Exception as e:
        print(e)
        flash('An error occurred while approving the user.', 'danger')
        return redirect(url_for('owner_dashboard'))


from flask_mail import Message


@app.route('/reject_user/<int:user_id>')
@role_required('owner')
def reject_user(user_id):
    try:
        user = db.session.get(User, user_id)

        user_email = user.email
        user_username = user.username
        if user.photo:
            photo_path = os.path.join(UPLOAD_FOLDER, user.photo)
            if os.path.exists(photo_path):
                os.remove(photo_path)

        if user.role == 'landlord':
            rooms = Room.query.filter_by(landlord_id=user.id).all()
            for room in rooms:
                bookings = Booking.query.filter_by(room_id=room.id).all()
                for booking in bookings:
                    db.session.delete(booking)
                db.session.delete(room)

        if user.role == 'boarder':
            bookings = Booking.query.filter_by(boarder_id=user.id).all()
            for booking in bookings:
                db.session.delete(booking)

        db.session.delete(user)
        db.session.commit()

        try:
            msg = Message("DormEZ Account Rejected", recipients=[user_email])
            msg.body = f"""Hello {user_username},

We regret to inform you that your DormEZ registration has been rejected by the admin.

If you believe this is a mistake or you have questions, please contact our support team.

Thank you,
DormEZ Team"""
            mail.send(msg)
            flash('❌ User rejected and notified via email.', 'warning')
        except Exception as email_error:
            print(f"Email error: {email_error}")
            flash('⚠️ User rejected, but email notification failed.',
                  'warning')

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error in reject_user: {e}")
        flash('❌ An error occurred while rejecting the user.', 'danger')

    return redirect(url_for('owner_dashboard'))


UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/add_room', methods=['GET', 'POST'])
@role_required('landlord')
def add_room():
    if request.method == 'POST':
        room_number = request.form['room_number']
        capacity = int(request.form['capacity'])
        rent_price = float(request.form['rent_price'])
        description = request.form.get('description')
        photo = request.files.get('photo')

        filename = None

        if photo and photo.filename != '':
            from werkzeug.utils import secure_filename
            filename = secure_filename(photo.filename)

            # Save to static/uploads
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(file_path)

        # ✅ Save filename in database
        new_room = Room(
            room_number=room_number,
            capacity=capacity,
            rent_price=rent_price,
            description=description,
            photo=filename,  # <== HERE! make sure it is filename
            landlord_id=session['user_id'],
            is_available=True)

        db.session.add(new_room)
        db.session.commit()
        flash('✅ Room added successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))

    return render_template('add_room.html')


@app.route('/book_room/<int:room_id>')
@role_required('boarder')
def book_room(room_id):
    try:
        room = Room.query.get_or_404(room_id)

        # ✅ Check if user already has an active booking for this room
        existing_booking = Booking.query.filter_by(
            room_id=room.id, boarder_id=session['user_id'],
            status='active').first()

        if existing_booking:
            flash('⚠️ You have already booked this room.', 'warning')
            return redirect(url_for('boarder_dashboard'))

        # Count current active bookings for this room
        current_count = Booking.query.filter_by(room_id=room.id,
                                                status='active').count()

        if current_count >= room.capacity:
            flash('Room is fully booked', 'danger')
            return redirect(url_for('boarder_dashboard'))

        # ✅ Create new booking
        new_booking = Booking(room_id=room.id,
                              boarder_id=session['user_id'],
                              start_date=datetime.utcnow())

        # Only mark as unavailable when full
        if current_count + 1 >= room.capacity:
            room.is_available = False

        db.session.add(new_booking)
        db.session.commit()

        flash(f'✅ Room {room.room_number} booked successfully!', 'success')
        return redirect(url_for('boarder_dashboard'))

    except Exception as e:
        logger.error(f"❌ Error in book_room: {e}")
        traceback.print_exc()
        db.session.rollback()
        return f"Booking error: {str(e)}", 500


@app.route('/logout')
def logout():
    try:
        session.clear()
        flash('You have been logged out successfully', 'info')
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"❌ Error in logout: {e}")
        return f"Logout error: {str(e)}", 500


# Initialize database
def init_db():
    try:
        logger.info("🔄 Initializing database...")
        with app.app_context():
            create_database_if_missing()
            db.create_all()

            # Create default admin user
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin',
                             password=generate_password_hash('admin123'),
                             email='admin@dormitory.com',
                             role='owner',
                             status='approved')
                db.session.add(admin)
                db.session.commit()
                logger.info(" Default admin user created: admin/admin123")
            else:
                logger.info(" Admin user already exists")

        logger.info(" Database initialization completed")
    except Exception as e:
        logger.error(f" Database initialization failed: {e}")
        traceback.print_exc()
        raise


if __name__ == '__main__':
    try:
        logger.info(" Starting Flask application...")

        # Test database connection first
        if not test_db_connection():
            logger.error(" Cannot start app - database connection failed")
            exit(1)

        init_db()
        logger.info(" App initialization successful, starting server...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        logger.error(f" Failed to start application: {e}")
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
