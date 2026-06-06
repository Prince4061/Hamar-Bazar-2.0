from flask import Flask, render_template, request, jsonify, redirect, session, g, send_file
import sqlite3
import os
import random
import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

from flask_wtf.csrf import CSRFProtect, CSRFError

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'hyperlocal_monopolistic_secret_key_12345')
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'marketplace.db'))

csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.path.startswith('/api/') or request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'error': 'CSRF token missing or invalid.', 'details': e.description}), 400
    return f"<h3>CSRF Error: {e.description}</h3><p>Please refresh the page and try again.</p>", 400

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'profile_pics')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

PRESC_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'prescriptions')
os.makedirs(PRESC_UPLOAD_FOLDER, exist_ok=True)

PAY_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'payments')
os.makedirs(PAY_UPLOAD_FOLDER, exist_ok=True)

def run_migrations():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception as e:
        print("Failed to set WAL mode:", e)
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN payment_mode TEXT DEFAULT 'COD'")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN payment_screenshot TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_suspicious INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN suspicion_reasons TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE delivery_partners ADD COLUMN password TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            keyword TEXT NOT NULL,
            searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
        )
        ''')
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

# Auto-initialize and seed database if it doesn't exist or is empty
if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
    try:
        import database
        database.init_db()
        database.seed_db()
        database.seed_historical_orders()
        database.seed_search_history()
    except Exception as e:
        print("Failed to auto-initialize database:", e)

run_migrations()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, timeout=30.0)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL;")
        except Exception as e:
            print("Failed to set WAL mode:", e)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def check_and_flag_suspicious_user(user_id, db):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        return
        
    reasons = []
    
    # 1. Suspicious Name checks
    name = user['name'].strip().lower()
    # Match keywords like test, fake, spam, guest, admin, null, undefined, placeholder
    suspicious_patterns = [r'test', r'fake', r'spam', r'guest', r'admin', r'null', r'undefined', r'dummy', r'placeholder', r'user\d+']
    if any(re.search(pat, name) for pat in suspicious_patterns):
        reasons.append("Name contains suspicious test/spam keywords")
    # Check if name contains numeric characters or special symbols (excluding space and dot)
    if not re.match(r'^[a-zA-Z\s\.]+$', user['name'].strip()):
        reasons.append("Name contains invalid characters (numbers or symbols)")
    if len(user['name'].strip()) < 3:
        reasons.append("Name is suspiciously short (< 3 characters)")
        
    # 2. Suspicious Phone checks
    phone = user['phone'].strip()
    # Normalize phone: remove non-digits
    phone_clean = ''.join(c for c in phone if c.isdigit())
    if phone_clean.startswith('91') and len(phone_clean) > 10:
        phone_clean = phone_clean[2:]
        
    # Check if number has repeating digits (e.g. 9999999999) or sequential (1234567890)
    if len(set(phone_clean)) <= 2:
        reasons.append("Phone number contains repeating digits")
    if phone_clean in ['1234567890', '0987654321', '123456789', '987654321']:
        reasons.append("Phone number matches a sequential placeholder pattern")
    if len(phone_clean) != 10:
        reasons.append(f"Phone number length is not standard ({len(phone_clean)} digits)")
        
    # 3. Transaction / Order checks in the last 24 hours
    one_day_ago = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        SELECT COUNT(id) as cnt, SUM(total_amount) as total 
        FROM orders 
        WHERE customer_id = ? AND created_at >= ? AND status != 'FAILED'
    """, (user_id, one_day_ago))
    stats = cursor.fetchone()
    
    if stats:
        cnt = stats['cnt'] or 0
        total = stats['total'] or 0.0
        if cnt >= 3:
            reasons.append(f"Placed too many orders ({cnt} orders) in the last 24 hours")
        if total > 5000:
            reasons.append(f"High transaction spending (₹{total:.2f}) in the last 24 hours")
            
    if reasons:
        reasons_str = "; ".join(reasons)
        cursor.execute("UPDATE users SET is_suspicious = 1, suspicion_reasons = ? WHERE id = ?", (reasons_str, user_id))
    else:
        cursor.execute("UPDATE users SET is_suspicious = 0, suspicion_reasons = NULL WHERE id = ?", (user_id,))
    db.commit()

@app.before_request
def check_user_and_shop_status():
    # Skip checking for static files
    if request.path.startswith('/static/'):
        return
        
    db = get_db()
    cursor = db.cursor()
    
    if session.get('role') == 'customer' and session.get('role_id'):
        try:
            cursor.execute("SELECT is_blocked FROM users WHERE id = ?", (session['role_id'],))
            row = cursor.fetchone()
            if row and row['is_blocked']:
                session.clear()
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Your account has been blocked due to security reasons. Please contact support.'}), 403
                return redirect('/login?error=blocked')
        except Exception as e:
            print("Failed to run check_user_blocked:", e)
            
    elif session.get('role') == 'vendor' and session.get('role_id'):
        try:
            cursor.execute("SELECT is_active FROM shops WHERE id = ?", (session['role_id'],))
            row = cursor.fetchone()
            if not row or not row['is_active']:
                session.clear()
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Unauthorized: Your vendor store is inactive.'}), 403
                return redirect('/staff-login?error=inactive')
        except Exception as e:
            print("Failed to run check_shop_active:", e)

# -------------------------------------------------------------
# Role Switcher & Mock Session
# -------------------------------------------------------------
@app.route('/session/switch')
def switch_session():
    # Only allowed in debug mode, or if logged in as admin
    if not app.debug and session.get('role') != 'admin':
        return "Access denied: Session switching is disabled in production.", 403
        
    role = request.args.get('role', 'customer')
    role_id = request.args.get('id', '1')
    
    session['role'] = role
    session['role_id'] = int(role_id)
    
    # Store additional names in session for UI greeting
    db = get_db()
    cursor = db.cursor()
    if role == 'customer':
        cursor.execute("SELECT name, profile_pic FROM users WHERE id = ?", (role_id,))
        row = cursor.fetchone()
        session['name'] = row['name'] if row else 'Customer'
        session['profile_pic'] = row['profile_pic'] if row else None
    elif role == 'vendor':
        cursor.execute("SELECT shop_name FROM shops WHERE id = ?", (role_id,))
        row = cursor.fetchone()
        session['name'] = row['shop_name'] if row else 'Vendor'
    elif role == 'delivery':
        cursor.execute("SELECT name FROM delivery_partners WHERE id = ?", (role_id,))
        row = cursor.fetchone()
        session['name'] = row['name'] if row else 'Delivery Boy'
    else:
        session['name'] = 'Super Admin'
        
    return redirect(request.referrer or f'/{role}')

@app.route('/session/logout')
def logout():
    session.clear()
    return redirect('/login')

# -------------------------------------------------------------
# Views Pages
# -------------------------------------------------------------
@app.route('/')
def home():
    # If no role selected, redirect to login page
    if 'role' not in session:
        return redirect('/login')
    return redirect(f"/{session['role']}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.json
        else:
            data = request.form
        phone = data.get('phone', '').strip().replace(" ", "").replace("-", "")
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        # Remove country code +91 if present
        if phone.startswith('+91'):
            phone = phone[3:]
        elif phone.startswith('91') and len(phone) > 10:
            phone = phone[2:]
            
        if not phone or not username:
            return jsonify({'success': False, 'error': 'Mobile number and username are required.'})
            
        # Validate phone contains only digits and is exactly 10 digits
        if not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'error': 'Please enter a valid 10-digit mobile number containing only numbers.'})
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE phone = ?", (phone,))
        user = cursor.fetchone()
        
        if user:
            if user['is_blocked']:
                return jsonify({'success': False, 'error': 'Your account has been blocked due to suspicious activity. Please contact support.'})
            # Enforce username verification
            if user['name'] and user['name'].strip().lower() != username.strip().lower():
                try:
                    cursor.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?, ?)", (username or phone, request.remote_addr))
                    db.commit()
                except Exception as e:
                    print("Failed to log failed login:", e)
                return jsonify({'success': False, 'error': 'Incorrect username for this mobile number.'})
            # Enforce password verification
            if not user['password']:
                return jsonify({'success': False, 'error': 'Account configuration error (missing password). Please contact support.'})
            if not check_password_hash(user['password'], password):
                # Record failed login in real table
                try:
                    cursor.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?, ?)", (username or phone, request.remote_addr))
                    db.commit()
                except Exception as e:
                    print("Failed to log failed login:", e)
                return jsonify({'success': False, 'error': 'Incorrect password for this account.'})
            
            # Keep credentials updated / validated
            check_and_flag_suspicious_user(user['id'], db)
            
            session['role'] = 'customer'
            session['role_id'] = user['id']
            session['name'] = user['name']
            session['profile_pic'] = user['profile_pic']
            return jsonify({'success': True, 'redirect': '/customer'})
        else:
            # Dynamically register/create a new customer if phone number doesn't exist
            # This implements "anyone can login by their credentials"
            new_address = "Sector 4, Local Area"
            try:
                hashed_pass = generate_password_hash(password)
                cursor.execute("INSERT INTO users (name, phone, address, password) VALUES (?, ?, ?, ?)", (username, phone, new_address, hashed_pass))
                db.commit()
                # Get the newly created user
                new_id = cursor.lastrowid
                
                # Run fraud check on registration!
                check_and_flag_suspicious_user(new_id, db)
                
                cursor.execute("SELECT * FROM users WHERE id = ?", (new_id,))
                user = cursor.fetchone()
                
                session['role'] = 'customer'
                session['role_id'] = user['id']
                session['name'] = user['name']
                session['profile_pic'] = user['profile_pic']
                return jsonify({'success': True, 'redirect': '/customer'})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to create user: {str(e)}'})
                
    return render_template('login.html')
@app.route('/staff-login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        if request.is_json:
            data = request.json
        else:
            data = request.form
        role = data.get('role', '').strip()  # admin, vendor, delivery
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '').strip()
        
        if not role or not identifier:
            return jsonify({'success': False, 'error': 'Role and ID are required.'})
            
        db = get_db()
        cursor = db.cursor()
        
        if role == 'admin':
            if identifier.strip().lower() != 'admin':
                return jsonify({'success': False, 'error': 'Incorrect username for Admin.'})
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
            if password != admin_pass:
                try:
                    cursor.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?, ?)", ('admin', request.remote_addr))
                    db.commit()
                except Exception as e:
                    print("Failed to log failed login:", e)
                return jsonify({'success': False, 'error': 'Incorrect password for Admin.'})
            # Admin login
            session['role'] = 'admin'
            session['role_id'] = 0
            session['name'] = 'Super Admin'
            return jsonify({'success': True, 'redirect': '/admin'})
            
        elif role == 'vendor':
            # Normalize common vendor aliases to seeded shops
            norm_id = identifier.lower().strip()
            if norm_id in ['kirana', 'grocery', 'general', 'apna', 'apna bazaar', 'apnabazaar', '1']:
                identifier = 'KIRANA'
            elif norm_id in ['cakes', 'cake', 'bakery', 'baker', 'bakers', '2']:
                identifier = 'CAKES'
            elif norm_id in ['veggies', 'vegetables', 'fresh', 'green', '3']:
                identifier = 'VEGGIES'
            elif norm_id in ['electronics', 'electro', 'electroworld', '4']:
                identifier = 'ELECTRONICS'
            elif norm_id in ['pharmacy', 'medicine', 'medicines', 'chemist', 'medical', '5']:
                identifier = 'PHARMACY'
            elif norm_id in ['tech', 'gadgets', 'accessories', 'hub', '6']:
                identifier = 'TECH'

            # Check if vendor identifier exists
            shop = None
            if identifier.isdigit():
                cursor.execute("SELECT * FROM shops WHERE id = ?", (int(identifier),))
                shop = cursor.fetchone()
            else:
                cursor.execute("SELECT * FROM shops WHERE shop_name LIKE ? OR category LIKE ?", (f"%{identifier}%", f"%{identifier}%"))
                shop = cursor.fetchone()
                
            if shop:
                if not shop['is_active']:
                    return jsonify({'success': False, 'error': 'This vendor store is currently inactive. Please contact Admin.'})
                # Verify password if one is set in the database
                if not shop['password']:
                    return jsonify({'success': False, 'error': 'Vendor store configuration error (missing password). Please contact Admin.'})
                if not check_password_hash(shop['password'], password):
                    try:
                        cursor.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?, ?)", (identifier, request.remote_addr))
                        db.commit()
                    except Exception as e:
                        print("Failed to log failed login:", e)
                    return jsonify({'success': False, 'error': 'Incorrect password for this vendor store.'})
            else:
                return jsonify({'success': False, 'error': 'Vendor store not registered. Please contact Admin.'})
            
            session['role'] = 'vendor'
            session['role_id'] = shop['id']
            session['name'] = shop['shop_name']
            return jsonify({'success': True, 'redirect': '/vendor'})
            
        elif role == 'delivery':
            rider = None
            # 1. Try to find by exact phone number match (removing spaces/dashes)
            clean_identifier = identifier.strip().replace(" ", "").replace("-", "")
            cursor.execute("SELECT * FROM delivery_partners WHERE phone = ?", (clean_identifier,))
            rider = cursor.fetchone()
            
            # 2. If not found by phone, and it is a digit, try by ID
            if not rider and identifier.isdigit():
                cursor.execute("SELECT * FROM delivery_partners WHERE id = ?", (int(identifier),))
                rider = cursor.fetchone()
                
            # 3. If still not found, try flexible name match
            if not rider:
                cursor.execute("SELECT * FROM delivery_partners WHERE name LIKE ?", (f"%{identifier}%",))
                rider = cursor.fetchone()
                
            if rider:
                if not rider['password']:
                    return jsonify({'success': False, 'error': 'Delivery rider configuration error (missing password). Please contact Admin.'})
                if not check_password_hash(rider['password'], password):
                    try:
                        cursor.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?, ?)", (identifier, request.remote_addr))
                        db.commit()
                    except Exception as e:
                        print("Failed to log failed login:", e)
                    return jsonify({'success': False, 'error': 'Incorrect password for this delivery rider.'})
            else:
                return jsonify({'success': False, 'error': 'Delivery rider not registered. Please contact Admin.'})
                    
            session['role'] = 'delivery'
            session['role_id'] = rider['id']
            session['name'] = rider['name']
            return jsonify({'success': True, 'redirect': '/delivery'})
            
        return jsonify({'success': False, 'error': 'Invalid role.'})
        
    return render_template('staff_login.html')



@app.route('/customer')
def customer_view():
    if session.get('role') != 'customer':
        return redirect('/login')
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    return render_template('customer.html', users=users, active_user_id=session.get('role_id'))

@app.route('/vendor')
def vendor_view():
    if session.get('role') != 'vendor':
        return redirect('/staff-login')
        
    db = get_db()
    cursor = db.cursor()
    # Enforce shop activity check
    shop_id = session.get('role_id')
    cursor.execute("SELECT is_active FROM shops WHERE id = ?", (shop_id,))
    shop = cursor.fetchone()
    if not shop or not shop['is_active']:
        session.clear()
        return redirect('/staff-login?error=inactive')
        
    cursor.execute("SELECT * FROM shops")
    shops = cursor.fetchall()
    
    return render_template('vendor.html', shops=shops, active_shop_id=session.get('role_id'))

@app.route('/delivery')
def delivery_view():
    if session.get('role') != 'delivery':
        return redirect('/staff-login')
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM delivery_partners")
    riders = cursor.fetchall()
        
    return render_template('delivery.html', riders=riders, active_rider_id=session.get('role_id'))

@app.route('/admin')
def admin_view():
    if session.get('role') != 'admin':
        return redirect('/staff-login')
        
    return render_template('admin.html')

# -------------------------------------------------------------
# REST APIs
# -------------------------------------------------------------

# --- Customer APIs ---

@app.route('/api/shops', methods=['GET'])
def get_shops():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM shops WHERE is_active = 1")
    shops = [dict(row) for row in cursor.fetchall()]
    return jsonify(shops)

@app.route('/api/shops/<int:shop_id>/products', methods=['GET'])
def get_shop_products(shop_id):
    db = get_db()
    cursor = db.cursor()
    # Verify shop is active if accessed by a customer
    is_vendor = request.args.get('view_type') == 'vendor'
    if not is_vendor:
        cursor.execute("SELECT is_active FROM shops WHERE id = ?", (shop_id,))
        shop = cursor.fetchone()
        if not shop or not shop['is_active']:
            return jsonify({'error': 'Shop is inactive or not found.'}), 404
            
    if is_vendor:
        cursor.execute("SELECT * FROM products WHERE shop_id = ?", (shop_id,))
    else:
        cursor.execute("SELECT * FROM products WHERE shop_id = ? AND is_available = 1", (shop_id,))
    products = [dict(row) for row in cursor.fetchall()]
    return jsonify(products)

@app.route('/api/products/sync', methods=['POST'])
def sync_products():
    if request.is_json:
        data = request.json
    else:
        data = request.form
    product_ids = data.get('product_ids', [])
    if not product_ids:
        return jsonify([])
        
    db = get_db()
    cursor = db.cursor()
    try:
        product_ids = [int(x) for x in product_ids]
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid product IDs.'}), 400
        
    if not product_ids:
        return jsonify([])
        
    placeholders = ','.join('?' for _ in product_ids)
    cursor.execute(f"SELECT id, name, price, is_available, shop_id, subcategory, description, image_path FROM products WHERE id IN ({placeholders})", product_ids)
    products = [dict(row) for row in cursor.fetchall()]
    return jsonify(products)

@app.route('/api/orders/place', methods=['POST'])
def place_order():
    data = request.json
    customer_id = data.get('customer_id')
    shop_id = data.get('shop_id')
    items = data.get('items', []) # List of {product_id, quantity}
    priority_type = data.get('priority_type', 'NORMAL').upper()
    
    if not customer_id or not shop_id or not items:
        return jsonify({'error': 'Missing checkout parameters.'}), 400
        
    # Prevent IDOR: Check that the logged-in user matches the customer_id placing the order
    if session.get('role') != 'customer' or session.get('role_id') != int(customer_id):
        return jsonify({'error': 'Unauthorized: You cannot place an order for another user.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    
    # Check if shop is active
    cursor.execute("SELECT is_active FROM shops WHERE id = ?", (shop_id,))
    shop = cursor.fetchone()
    if not shop or not shop['is_active']:
        return jsonify({'error': 'This shop is currently inactive/blocked and cannot accept orders.'}), 400
    
    # Calculate Total Amount & GST
    total_amount = 0.0
    products_details = []
    
    for item in items:
        prod_id = item.get('product_id')
        try:
            qty = int(item.get('quantity', 0))
        except (ValueError, TypeError):
            return jsonify({'error': 'Quantity must be a valid integer.'}), 400
        if qty <= 0:
            return jsonify({'error': 'Quantity must be a positive integer greater than zero.'}), 400
            
        cursor.execute("SELECT price, name, is_available FROM products WHERE id = ? AND shop_id = ?", (prod_id, shop_id))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({'error': f'Product {prod_id} not found in this shop.'}), 400
        if not prod['is_available']:
            return jsonify({'error': f"Product '{prod['name']}' is out of stock."}), 400
        item_total = prod['price'] * qty
        total_amount += item_total
        products_details.append({
            'product_id': prod_id,
            'quantity': qty,
            'price': prod['price']
        })
        
    # Delivery Fee & Grand Total Calculation matching mockup (Free above 199, else 15)
    delivery_fee = 15.0 if total_amount < 199.0 else 0.0
    grand_total = total_amount + delivery_fee
    gst_amount = 0.0 # GST is inclusive in item prices
    
    payment_mode = data.get('payment_mode', 'COD').upper()
    payment_screenshot = data.get('payment_screenshot')
    status = 'AWAITING_PAYMENT_APPROVAL' if payment_mode == 'ONLINE' else 'PENDING'
    
    # Generate OTPs (4 digits numeric)
    pickup_otp = f"{random.randint(1000, 9999)}"
    delivery_otp = f"{random.randint(1000, 9999)}"
    
    # Insert Order Master record
    cursor.execute('''
        INSERT INTO orders (customer_id, shop_id, total_amount, gst_amount, priority_type, status, pickup_otp, delivery_otp, payment_mode, payment_screenshot)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (customer_id, shop_id, grand_total, gst_amount, priority_type, status, pickup_otp, delivery_otp, payment_mode, payment_screenshot))
    
    order_id = cursor.lastrowid
    
    # Insert Order Items
    for pd in products_details:
        cursor.execute('''
            INSERT INTO order_items (order_id, product_id, quantity, price)
            VALUES (?, ?, ?, ?)
        ''', (order_id, pd['product_id'], pd['quantity'], pd['price']))
        
    db.commit()
    
    # Run security checks to flag suspicious user
    check_and_flag_suspicious_user(customer_id, db)
    
    return jsonify({
        'message': 'Order placed successfully!' if status == 'PENDING' else 'Payment verification pending!',
        'order_id': order_id,
        'pickup_otp': pickup_otp, # Kept for debugging/testing visibility if needed
        'delivery_otp': delivery_otp,
        'status': status
    })

@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order_details(order_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT o.*, s.shop_name, s.category, u.name as customer_name, u.address as customer_address, u.phone as customer_phone,
               dp.name as rider_name, dp.phone as rider_phone
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        JOIN users u ON o.customer_id = u.id
        LEFT JOIN delivery_partners dp ON o.delivery_boy_id = dp.id
        WHERE o.id = ?
    ''', (order_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
        
    # Prevent IDOR: Ensure caller is authorized (Customer, Shop Vendor, Delivery Rider, or Admin)
    role = session.get('role')
    role_id = session.get('role_id')
    
    is_authorized = False
    if role == 'admin':
        is_authorized = True
    elif role == 'customer' and role_id == order['customer_id']:
        is_authorized = True
    elif role == 'vendor' and role_id == order['shop_id']:
        is_authorized = True
    elif role == 'delivery' and role_id == order['delivery_boy_id']:
        is_authorized = True
        
    if not is_authorized:
        return jsonify({'error': 'Forbidden: You do not have permission to view this order.'}), 403
        
    # Get Items
    cursor.execute('''
        SELECT oi.*, p.name as product_name
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ?
    ''', (order_id,))
    items = [dict(row) for row in cursor.fetchall()]
    
    order_dict = dict(order)
    order_dict['items'] = items
    
    # Mask Rider phone number for security as specified in INT-008
    if order_dict['rider_phone']:
        ph = order_dict['rider_phone']
        order_dict['rider_phone_masked'] = ph[:3] + "xxxx" + ph[-3:] if len(ph) >= 6 else "xxxxxx"
        
    return jsonify(order_dict)

@app.route('/api/customer/<int:customer_id>/expenses', methods=['GET'])
def get_customer_expenses(customer_id):
    # Prevent IDOR: Check that the logged-in user matches the customer_id
    if session.get('role') != 'admin':
        if session.get('role') != 'customer' or session.get('role_id') != customer_id:
            return jsonify({'error': 'Forbidden: You cannot view expenses of other customers.'}), 403

    # Spending insights by category (INT-009)
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT s.category, SUM(o.total_amount) as total_spent, COUNT(o.id) as order_count
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        WHERE o.customer_id = ? AND o.status = 'DELIVERED'
        GROUP BY s.category
    ''', (customer_id,))
    rows = cursor.fetchall()
    
    categories = {}
    total_all = 0
    for r in rows:
        categories[r['category']] = {
            'spent': round(r['total_spent'], 2),
            'count': r['order_count']
        }
        total_all += r['total_spent']
        
    return jsonify({
        'categories': categories,
        'total_spent_overall': round(total_all, 2)
    })

@app.route('/api/customer/<int:customer_id>/orders', methods=['GET'])
def get_customer_orders(customer_id):
    # Prevent IDOR: Check that the logged-in user matches the customer_id
    if session.get('role') != 'admin':
        if session.get('role') != 'customer' or session.get('role_id') != customer_id:
            return jsonify({'error': 'Forbidden: You cannot view orders of other customers.'}), 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT o.id, o.created_at, o.total_amount, o.status, o.priority_type,
               s.shop_name, o.delivery_otp, o.pickup_otp
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        WHERE o.customer_id = ?
        ORDER BY o.id DESC
    ''', (customer_id,))
    orders = [dict(row) for row in cursor.fetchall()]
    return jsonify(orders)

@app.route('/api/customer/profile/update', methods=['POST'])
def update_profile():
    if session.get('role') != 'customer':
        return jsonify({'error': 'Unauthorized. Please login as customer.'}), 403
    if request.is_json:
        data = request.json
    else:
        data = request.form
    customer_id = data.get('customer_id')
    name = data.get('name', '').strip()
    address = data.get('address', '').strip()
    password = data.get('password', '').strip()
    
    if not customer_id or not name or not address or not password:
        return jsonify({'error': 'Name, Address, Password and Customer ID are required.'}), 400
        
    if int(customer_id) != session.get('role_id'):
        return jsonify({'error': 'Unauthorized. Customer ID does not match session.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET name = ?, address = ?, password = ? WHERE id = ?", (name, address, password, int(customer_id)))
        db.commit()
        session['name'] = name
        return jsonify({'success': True, 'message': 'Profile updated successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to update profile: {str(e)}'}), 500


@app.route('/api/customer/profile/upload_avatar', methods=['POST'])
def upload_avatar():
    if session.get('role') != 'customer':
        return jsonify({'error': 'Unauthorized. Please login as customer.'}), 403
        
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
        
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
        
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        customer_id = session.get('role_id')
        filename = f"profile_{customer_id}.{ext}"
        
        # Ensure upload folder exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        # Remove any other profile avatar files of this user with different extensions to avoid duplicate files
        for allowed_ext in ALLOWED_EXTENSIONS:
            old_filename = f"profile_{customer_id}.{allowed_ext}"
            old_path = os.path.join(UPLOAD_FOLDER, old_filename)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except Exception:
                    pass
                    
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Path relative to static/
        relative_path = f"/static/uploads/profile_pics/{filename}"
        
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (relative_path, customer_id))
            db.commit()
            session['profile_pic'] = relative_path
            return jsonify({'success': True, 'profile_pic': relative_path, 'message': 'Profile picture uploaded successfully.'})
        except Exception as e:
            return jsonify({'error': f'Database update failed: {str(e)}'}), 500
    else:
        return jsonify({'error': 'File type not allowed. Allowed types are png, jpg, jpeg, webp, gif.'}), 400

@app.route('/api/customer/profile/remove_avatar', methods=['POST'])
def remove_avatar():
    if session.get('role') != 'customer':
        return jsonify({'error': 'Unauthorized. Please login as customer.'}), 403
        
    customer_id = session.get('role_id')
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Get current path to delete file
        cursor.execute("SELECT profile_pic FROM users WHERE id = ?", (customer_id,))
        row = cursor.fetchone()
        if row and row['profile_pic']:
            relative_path = row['profile_pic']
            # Convert static path back to OS path
            static_prefix = "/static/"
            if relative_path.startswith(static_prefix):
                file_rel = relative_path[len(static_prefix):]
                abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', file_rel.replace('/', os.sep))
                if os.path.exists(abs_path):
                    try:
                        os.remove(abs_path)
                    except Exception:
                        pass
                        
        cursor.execute("UPDATE users SET profile_pic = NULL WHERE id = ?", (customer_id,))
        db.commit()
        session['profile_pic'] = None
        return jsonify({'success': True, 'message': 'Profile picture removed successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to remove profile picture: {str(e)}'}), 500

# --- Vendor APIs ---

@app.route('/api/vendor/orders/<int:shop_id>', methods=['GET'])
def get_vendor_orders(shop_id):
    if session.get('role') != 'vendor' or session.get('role_id') != shop_id:
        return jsonify({'error': 'Unauthorized.'}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT o.*, u.name as customer_name, u.address as customer_address, u.phone as customer_phone
        FROM orders o
        JOIN users u ON o.customer_id = u.id
        WHERE o.shop_id = ?
        ORDER BY 
            CASE WHEN o.priority_type = 'URGENT' AND o.status = 'PENDING' THEN 1 ELSE 2 END,
            o.id DESC
    ''', (shop_id,))
    orders = [dict(row) for row in cursor.fetchall()]
    return jsonify(orders)

@app.route('/api/orders/<int:order_id>/accept', methods=['POST'])
def accept_order(order_id):
    if session.get('role') != 'vendor':
        return jsonify({'error': 'Unauthorized. Please login as vendor.'}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status, shop_id FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
    if order['shop_id'] != session.get('role_id'):
        return jsonify({'error': 'Unauthorized for this shop.'}), 403
    if order['status'] != 'PENDING':
        return jsonify({'error': 'Order already processed.'}), 400
        
    cursor.execute('''
        UPDATE orders 
        SET status = 'ACCEPTED', accepted_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (order_id,))
    db.commit()
    return jsonify({'message': 'Order accepted successfully.'})

@app.route('/api/orders/<int:order_id>/ready', methods=['POST'])
def ready_order(order_id):
    if session.get('role') != 'vendor':
        return jsonify({'error': 'Unauthorized. Please login as vendor.'}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status, pickup_otp, shop_id FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
    if order['shop_id'] != session.get('role_id'):
        return jsonify({'error': 'Unauthorized for this shop.'}), 403
    if order['status'] != 'ACCEPTED':
        return jsonify({'error': 'Order must be ACCEPTED first.'}), 400
        
    cursor.execute('''
        UPDATE orders 
        SET status = 'READY_FOR_PICKUP', ready_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (order_id,))
    db.commit()
    return jsonify({
        'message': 'Order marked ready for pickup.',
        'pickup_otp': order['pickup_otp']
    })

@app.route('/api/vendor/products/toggle', methods=['POST'])
def toggle_product_availability():
    if session.get('role') != 'vendor':
        return jsonify({'error': 'Unauthorized. Please login as vendor.'}), 403
    data = request.json
    product_id = data.get('product_id')
    is_available = data.get('is_available')
    
    db = get_db()
    cursor = db.cursor()
    # verify product belongs to vendor's shop
    cursor.execute("SELECT shop_id FROM products WHERE id = ?", (product_id,))
    prod = cursor.fetchone()
    if not prod:
        return jsonify({'error': 'Product not found.'}), 404
    if prod['shop_id'] != session.get('role_id'):
        return jsonify({'error': 'Unauthorized for this product.'}), 403
        
    cursor.execute("UPDATE products SET is_available = ? WHERE id = ?", (is_available, product_id))
    db.commit()
    return jsonify({'message': 'Product availability updated.'})

@app.route('/api/vendor/low-stock-prediction/<int:shop_id>', methods=['GET'])
def get_low_stock_prediction(shop_id):
    if session.get('role') != 'vendor' or session.get('role_id') != shop_id:
        return jsonify({'error': 'Unauthorized.'}), 403
    # Frequently sold items low-stock prediction logic (INT-004)
    # We rank items that have been ordered the most, advising stock re-supply.
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT p.name, SUM(oi.quantity) as quantity_sold
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN orders o ON oi.order_id = o.id
        WHERE p.shop_id = ? AND o.status = 'DELIVERED'
        GROUP BY p.id
        ORDER BY quantity_sold DESC
        LIMIT 3
    ''', (shop_id,))
    rows = cursor.fetchall()
    predictions = []
    for row in rows:
        predictions.append({
            'name': row['name'],
            'message': f"High demand item ({row['quantity_sold']} units sold recently). Re-stock suggested to avoid outages!"
        })
    return jsonify(predictions)

# --- Delivery Rider APIs ---

@app.route('/api/delivery/pool', methods=['GET'])
def get_delivery_pool():
    if session.get('role') != 'delivery':
        return jsonify({'error': 'Unauthorized. Please login as delivery partner.'}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT o.*, s.shop_name, s.category, u.name as customer_name, u.address as customer_address
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        JOIN users u ON o.customer_id = u.id
        WHERE o.status = 'READY_FOR_PICKUP' AND o.delivery_boy_id IS NULL
        ORDER BY CASE WHEN o.priority_type = 'URGENT' THEN 1 ELSE 2 END, o.id ASC
    ''')
    orders = [dict(row) for row in cursor.fetchall()]
    return jsonify(orders)

@app.route('/api/orders/<int:order_id>/claim', methods=['POST'])
def claim_delivery(order_id):
    # Cooldown & assign claim (INT-003, ADMIN-003)
    if session.get('role') != 'delivery':
        return jsonify({'error': 'Unauthorized. Please login as delivery partner.'}), 403
        
    data = request.json
    rider_id = data.get('delivery_boy_id')
    
    if not rider_id:
        return jsonify({'error': 'Delivery Rider ID is required.'}), 400
        
    if int(rider_id) != session.get('role_id'):
        return jsonify({'error': 'Rider ID mismatch with session.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    
    # 1. Check Cooldown & Active Orders Limit
    cursor.execute("SELECT cooldown_until, active_orders FROM delivery_partners WHERE id = ?", (rider_id,))
    rider = cursor.fetchone()
    if not rider:
        return jsonify({'error': 'Rider not found.'}), 404
        
    if rider['active_orders'] and rider['active_orders'] >= 1:
        return jsonify({'error': 'You already have an active delivery job.'}), 400
        
    if rider['cooldown_until']:
        cooldown_dt = datetime.strptime(rider['cooldown_until'], '%Y-%m-%d %H:%M:%S' if '.' not in rider['cooldown_until'] else '%Y-%m-%d %H:%M:%S.%f')
        if datetime.now() < cooldown_dt:
            time_left = int((cooldown_dt - datetime.now()).total_seconds())
            return jsonify({'error': f'Cooldown mode active. Please wait {time_left} more seconds before claiming next job.'}), 400
            
    # 2. Check Order Availability with DB row-locking-like logic (Atomic claim check)
    db.execute("BEGIN TRANSACTION")
    cursor.execute("SELECT delivery_boy_id, status FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    
    if not order:
        db.execute("ROLLBACK")
        return jsonify({'error': 'Order not found.'}), 404
        
    if order['delivery_boy_id'] is not None:
        db.execute("ROLLBACK")
        return jsonify({'error': 'Order already claimed by another rider.'}), 400
        
    # 3. Commit claim & start 10-minute cooldown
    cooldown_end = datetime.now() + timedelta(minutes=10)
    
    cursor.execute('''
        UPDATE orders 
        SET delivery_boy_id = ?, assigned_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (rider_id, order_id))
    
    cursor.execute('''
        UPDATE delivery_partners 
        SET active_orders = active_orders + 1, cooldown_until = ?
        WHERE id = ?
    ''', (cooldown_end.strftime('%Y-%m-%d %H:%M:%S'), rider_id))
    
    db.commit()
    return jsonify({
        'message': 'Order claimed successfully! You have a 10-minute assignment cooldown for other orders.',
        'cooldown_until': cooldown_end.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/orders/<int:order_id>/verify-pickup', methods=['POST'])
def verify_pickup(order_id):
    if session.get('role') != 'delivery':
        return jsonify({'error': 'Unauthorized. Please login as delivery partner.'}), 403
    data = request.json
    entered_otp = data.get('otp')
    rider_id = data.get('delivery_boy_id')
    
    if not rider_id or int(rider_id) != session.get('role_id'):
        return jsonify({'error': 'Rider ID mismatch with session.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT pickup_otp, status, delivery_boy_id FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
    if order['delivery_boy_id'] != int(rider_id):
        return jsonify({'error': 'This order is not assigned to you.'}), 403
    if order['status'] != 'READY_FOR_PICKUP':
        return jsonify({'error': 'Order status must be READY FOR PICKUP.'}), 400
        
    if order['pickup_otp'] == entered_otp:
        cursor.execute("UPDATE orders SET status = 'OUT_FOR_DELIVERY' WHERE id = ?", (order_id,))
        db.commit()
        return jsonify({'message': 'Pickup OTP verified successfully. Status changed to OUT FOR DELIVERY.'})
    else:
        return jsonify({'error': 'Invalid Pickup OTP. Please check with shop vendor.'}), 400

@app.route('/api/orders/<int:order_id>/verify-delivery', methods=['POST'])
def verify_delivery(order_id):
    if session.get('role') != 'delivery':
        return jsonify({'error': 'Unauthorized. Please login as delivery partner.'}), 403
    data = request.json
    entered_otp = data.get('otp')
    rider_id = data.get('delivery_boy_id')
    
    if not rider_id or int(rider_id) != session.get('role_id'):
        return jsonify({'error': 'Rider ID mismatch with session.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT delivery_otp, status, delivery_boy_id FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
    if order['delivery_boy_id'] != int(rider_id):
        return jsonify({'error': 'This order is not assigned to you.'}), 403
    if order['status'] != 'OUT_FOR_DELIVERY':
        return jsonify({'error': 'Order status must be OUT FOR DELIVERY.'}), 400
        
    if order['delivery_otp'] == entered_otp:
        cursor.execute("UPDATE orders SET status = 'DELIVERED', delivered_at = CURRENT_TIMESTAMP WHERE id = ?", (order_id,))
        cursor.execute("UPDATE delivery_partners SET active_orders = MAX(0, active_orders - 1) WHERE id = ?", (int(rider_id),))
        db.commit()
        return jsonify({'message': 'Delivery OTP verified! Order successfully DELIVERED.'})
    else:
        return jsonify({'error': 'Invalid Delivery OTP. Please verify with Customer.'}), 400

# --- Payment Verification APIs ---

@app.route('/api/payments/upload-screenshot', methods=['POST'])
def upload_payment_screenshot():
    if session.get('role') != 'customer':
        return jsonify({'error': 'Unauthorized. Please login as customer.'}), 403
        
    if 'screenshot' not in request.files:
        return jsonify({'error': 'No screenshot file part.'}), 400
        
    file = request.files['screenshot']
    customer_id = session.get('role_id')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400
        
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"pay_{customer_id}_{int(datetime.now().timestamp())}.{ext}"
        
        file_path = os.path.join(PAY_UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Path relative to static/
        relative_path = f"/static/uploads/payments/{filename}"
        
        return jsonify({
            'success': True,
            'file_path': relative_path,
            'message': 'Screenshot uploaded successfully!'
        })
    else:
        return jsonify({'error': 'Invalid file type.'}), 400

@app.route('/api/admin/payments/pending', methods=['GET'])
def get_pending_payments():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT o.id, o.created_at, o.total_amount, o.payment_screenshot,
               u.name as customer_name, u.phone as customer_phone, s.shop_name
        FROM orders o
        JOIN users u ON o.customer_id = u.id
        JOIN shops s ON o.shop_id = s.id
        WHERE o.status = 'AWAITING_PAYMENT_APPROVAL'
        ORDER BY o.id DESC
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    return jsonify(rows)

@app.route('/api/admin/payments/<int:order_id>/approve', methods=['POST'])
def approve_order_payment(order_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'error': 'Order not found.'}), 404
    if row['status'] != 'AWAITING_PAYMENT_APPROVAL':
        return jsonify({'error': 'Order is not awaiting payment verification.'}), 400
        
    # Approve order: set status to PENDING and update created_at so it counts as placed now
    cursor.execute('''
        UPDATE orders 
        SET status = 'PENDING', created_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (order_id,))
    db.commit()
    return jsonify({'success': True, 'message': 'Payment approved. Order is now placed and visible to vendor.'})

@app.route('/api/admin/payments/<int:order_id>/reject', methods=['POST'])
def reject_order_payment(order_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'error': 'Order not found.'}), 404
    if row['status'] != 'AWAITING_PAYMENT_APPROVAL':
        return jsonify({'error': 'Order is not awaiting payment verification.'}), 400
        
    # Reject order: set status to FAILED and update failure reason
    cursor.execute('''
        UPDATE orders 
        SET status = 'FAILED', failure_reason = 'sahiiii payment wala screen shot bheje' 
        WHERE id = ?
    ''', (order_id,))
    db.commit()
    return jsonify({'success': True, 'message': 'Payment screenshot rejected. Order marked as FAILED.'})

# --- Admin Security Checker APIs ---

@app.route('/api/admin/suspicious-users', methods=['GET'])
def get_suspicious_users():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users")
    user_ids = [row['id'] for row in cursor.fetchall()]
    
    # Evaluate all users to dynamically detect suspicious activity
    for u_id in user_ids:
        check_and_flag_suspicious_user(u_id, db)
        
    # Return all suspicious or blocked users
    cursor.execute('''
        SELECT id, name, phone, address, is_blocked, is_suspicious, suspicion_reasons
        FROM users
        WHERE is_suspicious = 1 OR is_blocked = 1
        ORDER BY is_blocked ASC, is_suspicious DESC, id DESC
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    return jsonify(rows)

@app.route('/api/admin/users/<int:user_id>/block', methods=['POST'])
def block_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET is_blocked = 1 WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True, 'message': 'User account has been blocked successfully.'})

@app.route('/api/admin/users/<int:user_id>/unblock', methods=['POST'])
def unblock_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    # Unblock and clear suspicion reasons
    cursor.execute("UPDATE users SET is_blocked = 0, is_suspicious = 0, suspicion_reasons = NULL WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True, 'message': 'User account has been unblocked successfully.'})

# --- Admin APIs ---

@app.route('/api/admin/analytics', methods=['GET'])
def get_admin_analytics():
    start_time = datetime.now()
    db = get_db()
    cursor = db.cursor()
    
    # 1. High level aggregate stats
    cursor.execute("SELECT COUNT(id) FROM orders WHERE status = 'DELIVERED'")
    delivered_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(id) FROM orders WHERE status = 'FAILED' OR failure_reason IS NOT NULL")
    failed_count = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT SUM(total_amount) FROM orders WHERE status = 'DELIVERED'")
    total_rev = cursor.fetchone()[0] or 0.0
    
    cursor.execute("SELECT SUM(total_amount * (SELECT commission_pct FROM shops s WHERE s.id = orders.shop_id) / 100.0) FROM orders WHERE status = 'DELIVERED'")
    total_comm = cursor.fetchone()[0] or 0.0
    
    # Extra base stats
    cursor.execute("SELECT COUNT(*) FROM users")
    total_customers = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM delivery_partners")
    total_riders = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM delivery_partners WHERE availability_status = 'online'")
    online_riders = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT COUNT(*) FROM shops")
    total_vendors = cursor.fetchone()[0] or 0
    
    # Order Status counts
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'PENDING'")
    pending_count = cursor.fetchone()[0] or 0
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'ACCEPTED'")
    accepted_count = cursor.fetchone()[0] or 0
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'READY_FOR_PICKUP'")
    ready_count = cursor.fetchone()[0] or 0
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'OUT_FOR_DELIVERY'")
    transit_count = cursor.fetchone()[0] or 0
    cursor.execute("SELECT COUNT(*) FROM orders WHERE priority_type = 'URGENT'")
    urgent_count = cursor.fetchone()[0] or 0
    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'AWAITING_PAYMENT_APPROVAL'")
    awaiting_payment_count = cursor.fetchone()[0] or 0
    
    # Today vs Yesterday
    now = datetime.now()
    today_str = now.strftime('%Y-%m-%d')
    yesterday_str = (now - timedelta(days=1)).strftime('%Y-%m-%d')
    
    cursor.execute("SELECT COUNT(id), SUM(total_amount) FROM orders WHERE DATE(created_at) = ?", (today_str,))
    today_row = cursor.fetchone()
    today_orders = today_row[0] or 0
    today_revenue = round(today_row[1] or 0.0, 2)
    
    cursor.execute("SELECT COUNT(id), SUM(total_amount) FROM orders WHERE DATE(created_at) = ?", (yesterday_str,))
    yesterday_row = cursor.fetchone()
    yesterday_orders = yesterday_row[0] or 0
    yesterday_revenue = round(yesterday_row[1] or 0.0, 2)
    
    orders_growth = round(((today_orders - yesterday_orders) / yesterday_orders * 100.0), 1) if yesterday_orders > 0 else 12.5
    revenue_growth = round(((today_revenue - yesterday_revenue) / yesterday_revenue * 100.0), 1) if yesterday_revenue > 0.0 else 18.7
    
    # 2. Timing Analytics
    cursor.execute('''
        SELECT 
            AVG((julianday(delivered_at) - julianday(created_at)) * 1440.0) as avg_delivery,
            AVG((julianday(accepted_at) - julianday(created_at)) * 1440.0) as avg_acceptance,
            AVG((julianday(ready_at) - julianday(accepted_at)) * 1440.0) as avg_prep
        FROM orders 
        WHERE status = 'DELIVERED' 
          AND delivered_at IS NOT NULL 
          AND ready_at IS NOT NULL 
          AND accepted_at IS NOT NULL 
          AND created_at IS NOT NULL
    ''')
    times_row = cursor.fetchone()
    avg_delivery = round(times_row['avg_delivery'] or 32.4, 1)
    avg_acceptance = round(times_row['avg_acceptance'] or 3.2, 1)
    avg_prep = round(times_row['avg_prep'] or 12.8, 1)
    
    cursor.execute("SELECT COUNT(id) FROM orders")
    total_order_all = cursor.fetchone()[0] or 1
    delivery_completion_rate = round((delivered_count / total_order_all * 100.0), 1)
    
    # 3. Shop-wise sales & ratings (Vendor Reputation Score, INT-010, ADMIN-001)
    cursor.execute('''
        SELECT s.id as shop_id, s.shop_name, s.category, s.commission_pct, s.is_active, s.password, s.image_path,
               COUNT(o.id) as total_orders,
               SUM(CASE WHEN o.status = 'DELIVERED' THEN o.total_amount ELSE 0 END) as sales,
               SUM(CASE WHEN o.status = 'DELIVERED' THEN 1 ELSE 0 END) as success_orders,
               SUM(CASE WHEN o.status = 'FAILED' OR o.failure_reason IS NOT NULL THEN 1 ELSE 0 END) as failed_orders
        FROM shops s
        LEFT JOIN orders o ON s.id = o.shop_id
        GROUP BY s.id
    ''')
    shops_performance = [dict(row) for row in cursor.fetchall()]
    
    for sp in shops_performance:
        tot = sp['total_orders']
        sp['acceptance_rate'] = round((sp['success_orders'] / tot * 100), 1) if tot > 0 else 100.0
        sp['cancellation_rate'] = round((sp['failed_orders'] / tot * 100), 1) if tot > 0 else 0.0
        sp['avg_rating'] = round(4.0 + (sp['success_orders'] / tot * 0.9), 1) if tot > 0 else 5.0
        
    # 4. Peak order hours (Heatmap visual, INT-006, ADMIN-001)
    cursor.execute('''
        SELECT STRFTIME('%H', created_at) as hour, COUNT(id) as count
        FROM orders
        GROUP BY hour
        ORDER BY hour ASC
    ''')
    peak_times = {row['hour']: row['count'] for row in cursor.fetchall()}
    for h in range(24):
        h_str = f"{h:02d}"
        if h_str not in peak_times:
            peak_times[h_str] = 0
            
    # 5. Top Selling Products
    cursor.execute('''
        SELECT p.name, s.shop_name, SUM(oi.quantity) as sales_qty
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN shops s ON p.shop_id = s.id
        GROUP BY p.id
        ORDER BY sales_qty DESC
        LIMIT 5
    ''')
    top_products = [dict(row) for row in cursor.fetchall()]
    
    # 6. Order list for Admin details
    cursor.execute('''
        SELECT o.id, o.created_at, o.total_amount, o.status, o.priority_type,
               s.shop_name, u.name as customer_name, o.failure_reason
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        JOIN users u ON o.customer_id = u.id
        ORDER BY o.id DESC
        LIMIT 20
    ''')
    recent_orders = [dict(row) for row in cursor.fetchall()]
    
    # 7. Top Selling Areas
    cursor.execute('''
        SELECT u.address as area, COUNT(o.id) as order_count, SUM(o.total_amount) as sales
        FROM orders o
        JOIN users u ON o.customer_id = u.id
        GROUP BY u.address
        ORDER BY order_count DESC
        LIMIT 5
    ''')
    top_selling_areas = [dict(row) for row in cursor.fetchall()]
    
    # 8. Failed Order Reasons
    cursor.execute('''
        SELECT failure_reason, COUNT(*) as count 
        FROM orders 
        WHERE failure_reason IS NOT NULL 
        GROUP BY failure_reason
        ORDER BY count DESC
    ''')
    failed_order_reasons = [dict(row) for row in cursor.fetchall()]
    
    # 9. Riders Status
    cursor.execute("SELECT id, name, phone, availability_status, active_orders, cooldown_until, password FROM delivery_partners")
    riders_status = []
    for row in cursor.fetchall():
        r = dict(row)
        cooldown_secs = 0
        if r['cooldown_until']:
            try:
                cooldown_dt = datetime.strptime(r['cooldown_until'], '%Y-%m-%d %H:%M:%S' if '.' not in r['cooldown_until'] else '%Y-%m-%d %H:%M:%S.%f')
                if datetime.now() < cooldown_dt:
                    cooldown_secs = int((cooldown_dt - datetime.now()).total_seconds())
            except Exception:
                pass
        r['cooldown_secs'] = cooldown_secs
        riders_status.append(r)
        
    # 10. Customer retention analytics
    cursor.execute("SELECT customer_id, COUNT(id) as cnt FROM orders GROUP BY customer_id")
    user_orders = cursor.fetchall()
    returning_cnt = sum(1 for row in user_orders if row['cnt'] > 1)
    total_cust = len(user_orders)
    retention_rate = round((returning_cnt / total_cust * 100.0), 1) if total_cust > 0 else 82.4
    
    # 11. OTP Verification Logs
    cursor.execute('''
        SELECT o.id as order_id, o.pickup_otp, o.delivery_otp, o.status, o.delivered_at, o.ready_at,
               s.shop_name, dp.name as rider_name
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        LEFT JOIN delivery_partners dp ON o.delivery_boy_id = dp.id
        WHERE o.status IN ('OUT_FOR_DELIVERY', 'DELIVERED')
        ORDER BY o.id DESC
        LIMIT 10
    ''')
    otp_logs = []
    for row in cursor.fetchall():
        log = dict(row)
        log['pickup_time'] = log['ready_at'] or log['delivered_at']
        log['delivery_time'] = log['delivered_at']
        log['pickup_status'] = 'SUCCESS'
        log['delivery_status'] = 'SUCCESS' if log['status'] == 'DELIVERED' else 'PENDING'
        otp_logs.append(log)
        
    # 12. System Health & DB size
    db_size_kb = 0.0
    if os.path.exists(DB_PATH):
        db_size_kb = round(os.path.getsize(DB_PATH) / 1024.0, 1)
        
    # Get real failed login attempts from DB
    cursor.execute('''
        SELECT timestamp, username as user, ip_address as ip
        FROM failed_logins
        ORDER BY id DESC
        LIMIT 10
    ''')
    failed_logins_db = [dict(row) for row in cursor.fetchall()]

    # Real DB activity (order counts in last 8 hours)
    db_activity = []
    for i in range(7, -1, -1):
        dt = datetime.now() - timedelta(hours=i)
        dt_str = dt.strftime('%Y-%m-%d %H')
        cursor.execute("SELECT COUNT(*) FROM orders WHERE strftime('%Y-%m-%d %H', created_at) = ?", (dt_str,))
        count = cursor.fetchone()[0] or 0
        db_activity.append(count)

    # Actual request processing latency
    latency_ms = round((datetime.now() - start_time).total_seconds() * 1000.0, 1)

    system_health = {
        'db_size_kb': db_size_kb,
        'api_latency': f"{latency_ms}ms",
        'server_uptime': '99.99%',
        'db_activity': db_activity,
        'failed_logins': failed_logins_db
    }
    
    # 13. Real-time Stock Warnings / Low Stock predictions
    # A. Out of Stock products
    cursor.execute('''
        SELECT p.name, s.shop_name
        FROM products p
        JOIN shops s ON p.shop_id = s.id
        WHERE p.is_available = 0
        LIMIT 5
    ''')
    out_of_stock = [dict(row) for row in cursor.fetchall()]
    
    # B. High Demand products (frequently sold, low stock prediction)
    cursor.execute('''
        SELECT p.name, s.shop_name, SUM(oi.quantity) as quantity_sold
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN orders o ON oi.order_id = o.id
        JOIN shops s ON p.shop_id = s.id
        WHERE o.status = 'DELIVERED'
        GROUP BY p.id
        ORDER BY quantity_sold DESC
        LIMIT 5
    ''')
    high_demand = [dict(row) for row in cursor.fetchall()]

    stock_warnings = []
    for item in out_of_stock:
        stock_warnings.append({
            'name': item['name'],
            'shop': item['shop_name'],
            'left': 0,
            'state': 'Out of Stock'
        })
    for item in high_demand:
        stock_warnings.append({
            'name': item['name'],
            'shop': item['shop_name'],
            'left': item['quantity_sold'],
            'state': 'High Demand'
        })

    # 14. Category demand breakdown (INT-006)
    cursor.execute('''
        SELECT s.category, COUNT(o.id) as count
        FROM orders o
        JOIN shops s ON o.shop_id = s.id
        GROUP BY s.category
    ''')
    cat_rows = cursor.fetchall()
    category_demand = {row['category']: row['count'] for row in cat_rows}
    # Ensure all categories are present
    for cat in ['KIRANA', 'VEGGIES', 'CAKES', 'ELECTRONICS', 'PHARMACY', 'TECH']:
        if cat not in category_demand:
            category_demand[cat] = 0

    return jsonify({
        'overview': {
            'delivered_count': delivered_count,
            'failed_count': failed_count,
            'total_revenue': round(total_rev, 2),
            'total_commission': round(total_comm, 2),
            'total_customers': total_customers,
            'total_riders': total_riders,
            'online_riders': online_riders,
            'total_vendors': total_vendors,
            'pending_count': pending_count,
            'accepted_count': accepted_count,
            'ready_count': ready_count,
            'transit_count': transit_count,
            'urgent_count': urgent_count,
            'today_orders': today_orders,
            'today_revenue': today_revenue,
            'yesterday_orders': yesterday_orders,
            'yesterday_revenue': yesterday_revenue,
            'orders_growth': orders_growth,
            'revenue_growth': revenue_growth,
            'awaiting_payment_count': awaiting_payment_count
        },
        'timing_analytics': {
            'avg_delivery_time': avg_delivery,
            'avg_acceptance_time': avg_acceptance,
            'avg_prep_time': avg_prep,
            'delivery_completion_rate': delivery_completion_rate
        },
        'shops_performance': shops_performance,
        'peak_times': peak_times,
        'top_products': top_products,
        'recent_orders': recent_orders,
        'top_selling_areas': top_selling_areas,
        'failed_order_reasons': failed_order_reasons,
        'riders_status': riders_status,
        'retention_rate': retention_rate,
        'otp_logs': otp_logs,
        'system_health': system_health,
        'stock_warnings': stock_warnings,
        'category_demand': category_demand
    })


@app.route('/api/admin/shops/<int:shop_id>/update', methods=['POST'])
def admin_update_shop(shop_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    shop_name = data.get('shop_name', '').strip()
    category = data.get('category', '').strip().upper()
    commission_pct = data.get('commission_pct', '5.0')
    password = data.get('password', '').strip()
    
    if not shop_name or not category:
        return jsonify({'error': 'Shop Name and Category Code are required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id FROM shops WHERE category = ? AND id != ?", (category, shop_id))
    if cursor.fetchone():
        return jsonify({'error': f'Category/Shop with code "{category}" already exists.'}), 400
        
    # Get current image path
    cursor.execute("SELECT image_path FROM shops WHERE id = ?", (shop_id,))
    current_shop = cursor.fetchone()
    image_path = current_shop['image_path'] if current_shop else '/static/images/grocery_basket.png'
    
    # Handle image URL from form
    image_url = data.get('shop_image_url', '').strip()
    if image_url:
        image_path = image_url
        
    # Handle image upload if form contains files
    if 'shop_image' in request.files:
        file = request.files['shop_image']
        if file and file.filename != '' and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"category_{category.lower()}_{int(datetime.now().timestamp())}.{ext}"
            upload_path = os.path.join(app.root_path, 'static', 'uploads', 'category_pics')
            os.makedirs(upload_path, exist_ok=True)
            file_path = os.path.join(upload_path, filename)
            file.save(file_path)
            image_path = f"/static/uploads/category_pics/{filename}"
            
    try:
        cursor.execute('''
            UPDATE shops 
            SET shop_name = ?, category = ?, commission_pct = ?, password = ?, image_path = ? 
            WHERE id = ?
        ''', (shop_name, category, float(commission_pct), password, image_path, shop_id))
        db.commit()
        return jsonify({'success': True, 'message': 'Shop category credentials updated successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to update shop: {str(e)}'}), 500


@app.route('/api/admin/delivery/add', methods=['POST'])
def admin_add_delivery_partner():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip().replace(" ", "").replace("-", "")
    password = data.get('password', '').strip()
    
    if not name or not phone or not password:
        return jsonify({'error': 'Name, Phone Number, and Password are required.'}), 400
        
    # Validate phone contains only digits and is exactly 10 digits
    if not phone.isdigit() or len(phone) != 10:
        return jsonify({'error': 'Please enter a valid 10-digit phone number containing only numbers.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id FROM delivery_partners WHERE phone = ?", (phone,))
    if cursor.fetchone():
        return jsonify({'error': f'Delivery partner with phone number "{phone}" already exists.'}), 400
        
    try:
        cursor.execute('''
            INSERT INTO delivery_partners (name, phone, password, availability_status, active_orders)
            VALUES (?, ?, ?, 'online', 0)
        ''', (name, phone, password))
        db.commit()
        return jsonify({'success': True, 'message': 'Delivery partner added successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to add delivery partner: {str(e)}'}), 500


@app.route('/api/admin/delivery/<int:rider_id>/update', methods=['POST'])
def admin_update_delivery_partner(rider_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    if request.is_json:
        data = request.json
    else:
        data = request.form
        
    name = data.get('name', '').strip()
    phone = data.get('phone', '').strip().replace(" ", "").replace("-", "")
    password = data.get('password', '').strip()
    
    if not name or not phone or not password:
        return jsonify({'error': 'Name, Phone Number, and Password are required.'}), 400
        
    # Validate phone contains only digits and is exactly 10 digits
    if not phone.isdigit() or len(phone) != 10:
        return jsonify({'error': 'Please enter a valid 10-digit phone number containing only numbers.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id FROM delivery_partners WHERE phone = ? AND id != ?", (phone, rider_id))
    if cursor.fetchone():
        return jsonify({'error': f'Delivery partner with phone number "{phone}" already exists.'}), 400
        
    try:
        cursor.execute('''
            UPDATE delivery_partners 
            SET name = ?, phone = ?, password = ? 
            WHERE id = ?
        ''', (name, phone, password, rider_id))
        db.commit()
        return jsonify({'success': True, 'message': 'Delivery partner credentials updated successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to update delivery partner: {str(e)}'}), 500


@app.route('/api/admin/shops/<int:shop_id>/toggle', methods=['POST'])
def toggle_shop_active(shop_id):
    data = request.json or {}
    is_active = data.get('is_active', 1)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE shops SET is_active = ? WHERE id = ?", (int(is_active), shop_id))
    db.commit()
    return jsonify({'success': True, 'message': 'Shop status updated successfully.'})


@app.route('/api/admin/shops/add', methods=['POST'])
def admin_add_shop():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    shop_name = request.form.get('shop_name', '').strip()
    category = request.form.get('category', '').strip().upper()
    commission_pct = request.form.get('commission_pct', '5.0').strip()
    password = request.form.get('password', '').strip()
    
    if not shop_name or not category:
        return jsonify({'error': 'Shop Name and Category Code are required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    # Check if category already exists
    cursor.execute("SELECT id FROM shops WHERE category = ?", (category,))
    if cursor.fetchone():
        return jsonify({'error': f'Category/Shop with code "{category}" already exists.'}), 400
        
    # Handle image upload
    image_path = '/static/images/grocery_basket.png' # default placeholder
    
    # Check if image URL was provided
    image_url = request.form.get('shop_image_url', '').strip()
    if image_url:
        image_path = image_url
        
    if 'shop_image' in request.files:
        file = request.files['shop_image']
        if file and file.filename != '' and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"category_{category.lower()}_{int(datetime.now().timestamp())}.{ext}"
            upload_path = os.path.join(app.root_path, 'static', 'uploads', 'category_pics')
            os.makedirs(upload_path, exist_ok=True)
            file_path = os.path.join(upload_path, filename)
            file.save(file_path)
            image_path = f"/static/uploads/category_pics/{filename}"
            
    try:
        cursor.execute('''
            INSERT INTO shops (shop_name, category, commission_pct, password, image_path, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (shop_name, category, float(commission_pct), password, image_path))
        db.commit()
        
        # Dynamic seeding of 3 starter products for the new shop
        shop_id = cursor.lastrowid
        cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop_id, 'Standard Product A', 100.0))
        cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop_id, 'Standard Product B', 200.0))
        cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop_id, 'Standard Product C', 350.0))
        db.commit()
        
        return jsonify({'success': True, 'message': 'New Shop Category added successfully with credentials and starter products.', 'shop_id': shop_id})
    except Exception as e:
        return jsonify({'error': f'Failed to create shop category: {str(e)}'}), 500

@app.route('/api/admin/products/upload-image', methods=['POST'])
def upload_product_image():
    if 'product_image' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
    file = request.files['product_image']
    prod_id = request.form.get('product_id')
    if not prod_id:
        return jsonify({'error': 'Product ID is required.'}), 400
        
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"product_{prod_id}_{int(datetime.now().timestamp())}.{ext}"
        upload_path = os.path.join(app.root_path, 'static', 'uploads', 'product_pics')
        os.makedirs(upload_path, exist_ok=True)
        file_path = os.path.join(upload_path, filename)
        file.save(file_path)
        
        db_path = f"/static/uploads/product_pics/{filename}"
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE products SET image_path = ? WHERE id = ?", (db_path, int(prod_id)))
        db.commit()
        return jsonify({'success': True, 'image_path': db_path, 'message': 'Product image uploaded successfully.'})
    return jsonify({'error': 'Invalid file type.'}), 400

@app.route('/api/admin/products', methods=['POST'])
def admin_add_product():
    data = request.json
    shop_id = data.get('shop_id')
    name = data.get('name')
    price = data.get('price')
    image_path = data.get('image_path')
    subcategory = data.get('subcategory', '')
    description = data.get('description', '')
    
    if not shop_id or not name or price is None:
        return jsonify({'error': 'Parameters shop_id, name, and price are required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO products (shop_id, name, price, image_path, subcategory, description) VALUES (?, ?, ?, ?, ?, ?)", (shop_id, name, float(price), image_path, subcategory, description))
    db.commit()
    return jsonify({'message': 'Product added successfully.', 'id': cursor.lastrowid})

@app.route('/api/admin/products/<int:prod_id>', methods=['PUT', 'DELETE'])
def admin_modify_product(prod_id):
    db = get_db()
    cursor = db.cursor()
    if request.method == 'DELETE':
        cursor.execute("DELETE FROM products WHERE id = ?", (prod_id,))
        db.commit()
        return jsonify({'message': 'Product deleted successfully.'})
        
    elif request.method == 'PUT':
        data = request.json
        name = data.get('name')
        price = data.get('price')
        is_available = data.get('is_available', 1)
        image_path = data.get('image_path')
        subcategory = data.get('subcategory', '')
        description = data.get('description', '')
        
        cursor.execute('''
            UPDATE products 
            SET name = ?, price = ?, is_available = ?, image_path = ?, subcategory = ?, description = ? 
            WHERE id = ?
        ''', (name, float(price), int(is_available), image_path, subcategory, description, prod_id))
        db.commit()
        return jsonify({'message': 'Product updated successfully.'})

# --- System Settings APIs ---
@app.route('/api/system/settings', methods=['GET'])
def get_system_settings():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT key, value FROM system_settings")
    rows = cursor.fetchall()
    settings = {row['key']: row['value'] for row in rows}
    if 'about_team_image' not in settings:
        settings['about_team_image'] = ''
    return jsonify(settings)

@app.route('/api/admin/settings/upload-team-photo', methods=['POST'])
def upload_team_photo():
    if 'team_photo' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['team_photo']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
        
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"team_photo_{int(datetime.now().timestamp())}.{ext}"
        upload_path = os.path.join(app.root_path, 'static', 'uploads', 'system')
        os.makedirs(upload_path, exist_ok=True)
        file_path = os.path.join(upload_path, filename)
        file.save(file_path)
        
        db_path = f"/static/uploads/system/{filename}"
        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('about_team_image', ?)", (db_path,))
        db.commit()
        return jsonify({'success': True, 'image_path': db_path, 'message': 'Team photo uploaded successfully.'})
    return jsonify({'error': 'Invalid file type.'}), 400

@app.route('/api/admin/settings/team-photo', methods=['DELETE'])
def delete_team_photo():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM system_settings WHERE key = 'about_team_image'")
    db.commit()
    return jsonify({'success': True, 'message': 'Team photo deleted successfully.'})

# --- Rider Active Job & Status APIs ---
@app.route('/api/delivery/rider/<int:rider_id>/active', methods=['GET'])
def get_rider_active_order(rider_id):
    if session.get('role') != 'delivery' or session.get('role_id') != rider_id:
        return jsonify({'error': 'Unauthorized.'}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT id FROM orders 
        WHERE delivery_boy_id = ? AND status NOT IN ('DELIVERED', 'FAILED')
        LIMIT 1
    ''', (rider_id,))
    row = cursor.fetchone()
    if row:
        return jsonify({'active_order_id': row['id']})
    return jsonify({'active_order_id': None})

@app.route('/api/delivery/rider/<int:rider_id>/status', methods=['GET'])
def get_rider_status(rider_id):
    if session.get('role') != 'delivery' or session.get('role_id') != rider_id:
        return jsonify({'error': 'Unauthorized.'}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT cooldown_until, active_orders, availability_status FROM delivery_partners WHERE id = ?", (rider_id,))
    row = cursor.fetchone()
    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'Rider not found'}), 404

# --- Cooldown timer reset route (For easy debugging/demo) ---
@app.route('/api/delivery/rider/<int:rider_id>/reset-cooldown', methods=['POST'])
def reset_rider_cooldown(rider_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE delivery_partners SET cooldown_until = NULL, active_orders = 0 WHERE id = ?", (rider_id,))
    db.commit()
    return jsonify({'message': 'Rider cooldown and active orders reset.'})


# --- Prescription / Medicine Upload APIs ---

@app.route('/api/prescriptions/upload', methods=['POST'])
def upload_prescription():
    if session.get('role') != 'customer':
        return jsonify({'error': 'Unauthorized. Please login as customer.'}), 403
        
    if 'prescription_image' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
        
    file = request.files['prescription_image']
    customer_id = session.get('role_id')
    
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
        
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"presc_{customer_id}_{int(datetime.now().timestamp())}.{ext}"
        
        # Ensure upload folder exists
        os.makedirs(PRESC_UPLOAD_FOLDER, exist_ok=True)
        
        file_path = os.path.join(PRESC_UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Path relative to static/
        relative_path = f"/static/uploads/prescriptions/{filename}"
        
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('''
                INSERT INTO prescription_requests (customer_id, image_path, status)
                VALUES (?, ?, 'PENDING')
            ''', (customer_id, relative_path))
            db.commit()
            return jsonify({'success': True, 'image_path': relative_path, 'message': 'Medicine image uploaded successfully.'})
        except Exception as e:
            return jsonify({'error': f'Database saving failed: {str(e)}'}), 500
    else:
        return jsonify({'error': 'File type not allowed.'}), 400

@app.route('/api/prescriptions/customer/<int:cust_id>', methods=['GET'])
def get_customer_prescriptions(cust_id):
    if session.get('role') != 'customer' or session.get('role_id') != cust_id:
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT pr.*, s.shop_name 
        FROM prescription_requests pr
        LEFT JOIN shops s ON pr.shop_id = s.id
        WHERE pr.customer_id = ?
        ORDER BY pr.id DESC
    ''', (cust_id,))
    rows = [dict(row) for row in cursor.fetchall()]
    return jsonify(rows)

@app.route('/api/admin/prescriptions', methods=['GET'])
def get_admin_prescriptions():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT pr.*, u.name as customer_name, u.phone as customer_phone, s.shop_name 
        FROM prescription_requests pr
        JOIN users u ON pr.customer_id = u.id
        LEFT JOIN shops s ON pr.shop_id = s.id
        ORDER BY pr.id DESC
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    return jsonify(rows)

@app.route('/api/admin/prescriptions/<int:req_id>/forward', methods=['POST'])
def forward_prescription(req_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    data = request.json or {}
    shop_id = data.get('shop_id')
    
    if not shop_id:
        return jsonify({'error': 'Shop ID is required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id FROM prescription_requests WHERE id = ?", (req_id,))
    if not cursor.fetchone():
        return jsonify({'error': 'Request not found.'}), 404
        
    cursor.execute('''
        UPDATE prescription_requests 
        SET shop_id = ?, status = 'SENT_TO_VENDOR' 
        WHERE id = ?
    ''', (int(shop_id), req_id))
    db.commit()
    return jsonify({'success': True, 'message': 'Prescription forwarded to medical shop successfully.'})

@app.route('/api/vendor/prescriptions/<int:shop_id>', methods=['GET'])
def get_vendor_prescriptions(shop_id):
    if session.get('role') != 'vendor' or session.get('role_id') != shop_id:
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT pr.*, u.name as customer_name, u.phone as customer_phone, u.address as customer_address
        FROM prescription_requests pr
        JOIN users u ON pr.customer_id = u.id
        WHERE pr.shop_id = ?
        ORDER BY pr.id DESC
    ''', (shop_id,))
    rows = [dict(row) for row in cursor.fetchall()]
    return jsonify(rows)

@app.route('/api/vendor/prescriptions/<int:req_id>/complete', methods=['POST'])
def complete_prescription(req_id):
    if session.get('role') != 'vendor':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    shop_id = session.get('role_id')
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id, shop_id FROM prescription_requests WHERE id = ?", (req_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'error': 'Request not found.'}), 404
    if row['shop_id'] != shop_id:
        return jsonify({'error': 'Unauthorized for this shop.'}), 403
        
    cursor.execute("UPDATE prescription_requests SET status = 'COMPLETED' WHERE id = ?", (req_id,))
    db.commit()
    return jsonify({'success': True, 'message': 'Prescription marked as complete/quoted.'})

# --- Customer Search Intelligence API Endpoints ---

@app.route('/api/search/track', methods=['POST'])
def track_search():
    if request.is_json:
        data = request.json
    else:
        data = request.form
    customer_id = data.get('customer_id')
    keyword = data.get('keyword', '').strip().lower()
    
    if not customer_id or not keyword:
        return jsonify({'error': 'Customer ID and keyword are required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO search_history (customer_id, keyword) VALUES (?, ?)", (int(customer_id), keyword))
        db.commit()
        return jsonify({'success': True, 'message': 'Search tracked successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to track search: {str(e)}'}), 500

@app.route('/api/admin/search-analytics', methods=['GET'])
def get_search_analytics():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    
    # 1. Top Trending Searches (all time)
    cursor.execute('''
        SELECT keyword, COUNT(*) as count 
        FROM search_history 
        GROUP BY keyword 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    trending = [dict(row) for row in cursor.fetchall()]
    
    # 2. Most Active Searchers
    cursor.execute('''
        SELECT u.id, u.name, COUNT(sh.id) as count
        FROM search_history sh
        JOIN users u ON sh.customer_id = u.id
        GROUP BY sh.customer_id
        ORDER BY count DESC
        LIMIT 10
    ''')
    active_searchers = [dict(row) for row in cursor.fetchall()]
    
    # 3. Today's Top Searches
    cursor.execute('''
        SELECT keyword, COUNT(*) as count 
        FROM search_history 
        WHERE DATE(searched_at) = DATE('now', 'localtime')
        GROUP BY keyword 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    today_top = [dict(row) for row in cursor.fetchall()]
    
    # 4. Weekly Top Searches
    cursor.execute('''
        SELECT keyword, COUNT(*) as count 
        FROM search_history 
        WHERE searched_at >= datetime('now', '-7 days')
        GROUP BY keyword 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    weekly_top = [dict(row) for row in cursor.fetchall()]
    
    # 5. Monthly Top Searches
    cursor.execute('''
        SELECT keyword, COUNT(*) as count 
        FROM search_history 
        WHERE searched_at >= datetime('now', '-30 days')
        GROUP BY keyword 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    monthly_top = [dict(row) for row in cursor.fetchall()]
    
    # 6. Customer Summary List (all customers, with search counts)
    cursor.execute('''
        SELECT u.id, u.name, u.phone, u.address,
               (SELECT COUNT(*) FROM search_history WHERE customer_id = u.id) as total_searches,
               (SELECT keyword FROM search_history WHERE customer_id = u.id ORDER BY id DESC LIMIT 1) as last_search_keyword,
               (SELECT searched_at FROM search_history WHERE customer_id = u.id ORDER BY id DESC LIMIT 1) as last_search_time
        FROM users u
        ORDER BY last_search_time DESC, u.id DESC
    ''')
    customers_summary = []
    for row in cursor.fetchall():
        r = dict(row)
        if r['last_search_time']:
            try:
                dt = datetime.strptime(r['last_search_time'], '%Y-%m-%d %H:%M:%S' if '.' not in r['last_search_time'] else '%Y-%m-%d %H:%M:%S.%f')
                r['last_search_time_formatted'] = dt.strftime('%d %b %Y %I:%M %p')
            except Exception:
                r['last_search_time_formatted'] = r['last_search_time']
        else:
            r['last_search_time_formatted'] = '--'
            
        # Fetch up to 5 unique recent keywords
        temp_cursor = db.cursor()
        temp_cursor.execute('''
            SELECT keyword FROM search_history 
            WHERE customer_id = ? 
            ORDER BY id DESC
        ''', (r['id'],))
        seen_kws = set()
        recent_kws = []
        for s_row in temp_cursor.fetchall():
            kw = s_row[0]
            if kw not in seen_kws:
                seen_kws.add(kw)
                recent_kws.append(kw)
                if len(recent_kws) >= 5:
                    break
        r['recent_keywords'] = recent_kws
        customers_summary.append(r)
        
    # 7. Recent Search Logs (latest 100 searches on the platform)
    cursor.execute('''
        SELECT sh.id, sh.keyword, sh.searched_at, u.id as customer_id, u.name as customer_name
        FROM search_history sh
        JOIN users u ON sh.customer_id = u.id
        ORDER BY sh.id DESC
        LIMIT 100
    ''')
    recent_searches = []
    for row in cursor.fetchall():
        r = dict(row)
        if r['searched_at']:
            try:
                dt = datetime.strptime(r['searched_at'], '%Y-%m-%d %H:%M:%S' if '.' not in r['searched_at'] else '%Y-%m-%d %H:%M:%S.%f')
                r['searched_at_formatted'] = dt.strftime('%d %b %Y %I:%M %p')
            except Exception:
                r['searched_at_formatted'] = r['searched_at']
        else:
            r['searched_at_formatted'] = '--'
        recent_searches.append(r)
        
    return jsonify({
        'trending': trending,
        'active_searchers': active_searchers,
        'today_top': today_top,
        'weekly_top': weekly_top,
        'monthly_top': monthly_top,
        'customers_summary': customers_summary,
        'recent_searches': recent_searches
    })

@app.route('/api/admin/customer/<int:cust_id>/search-profile', methods=['GET'])
def get_customer_search_profile(cust_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    db = get_db()
    cursor = db.cursor()
    
    # Fetch Customer basic details
    cursor.execute("SELECT id, name, phone, address FROM users WHERE id = ?", (cust_id,))
    user_row = cursor.fetchone()
    if not user_row:
        return jsonify({'error': 'Customer not found.'}), 404
        
    user_details = dict(user_row)
    
    # Total Orders count
    cursor.execute("SELECT COUNT(*) FROM orders WHERE customer_id = ?", (cust_id,))
    total_orders = cursor.fetchone()[0] or 0
    
    # Total Spending
    cursor.execute("SELECT SUM(total_amount) FROM orders WHERE customer_id = ? AND status = 'DELIVERED'", (cust_id,))
    total_spending = cursor.fetchone()[0] or 0.0
    
    # Complete Search History
    cursor.execute("SELECT keyword, searched_at FROM search_history WHERE customer_id = ? ORDER BY id DESC", (cust_id,))
    history = []
    for row in cursor.fetchall():
        h = dict(row)
        try:
            dt = datetime.strptime(h['searched_at'], '%Y-%m-%d %H:%M:%S' if '.' not in h['searched_at'] else '%Y-%m-%d %H:%M:%S.%f')
            h['searched_at_formatted'] = dt.strftime('%d %b %Y %I:%M %p')
        except Exception:
            h['searched_at_formatted'] = h['searched_at']
        history.append(h)
        
    # Last Search Time
    last_search_time_formatted = '--'
    if history:
        last_search_time_formatted = history[0]['searched_at_formatted']
        
    # Most Searched Keyword
    cursor.execute('''
        SELECT keyword, COUNT(*) as count 
        FROM search_history 
        WHERE customer_id = ? 
        GROUP BY keyword 
        ORDER BY count DESC 
        LIMIT 1
    ''', (cust_id,))
    most_searched_row = cursor.fetchone()
    most_searched = 'None'
    if most_searched_row:
        most_searched = f"{most_searched_row['keyword']} ({most_searched_row['count']} searches)"
        
    return jsonify({
        'customer': user_details,
        'total_orders': total_orders,
        'total_spending': round(total_spending, 2),
        'history': history,
        'last_search_time': last_search_time_formatted,
        'most_searched_product': most_searched
    })

@app.route('/api/admin/customer/<int:cust_id>/export-pdf', methods=['GET'])
def export_customer_search_pdf(cust_id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403
        
    db = get_db()
    cursor = db.cursor()
    
    # Fetch Customer Details
    cursor.execute("SELECT name, phone, address FROM users WHERE id = ?", (cust_id,))
    user = cursor.fetchone()
    if not user:
        return "Customer not found", 404
        
    # Fetch Search Stats
    cursor.execute("SELECT COUNT(*) FROM search_history WHERE customer_id = ?", (cust_id,))
    total_searches = cursor.fetchone()[0] or 0
    
    cursor.execute('''
        SELECT keyword, COUNT(*) as count 
        FROM search_history 
        WHERE customer_id = ? 
        GROUP BY keyword 
        ORDER BY count DESC 
        LIMIT 5
    ''', (cust_id,))
    top_keywords = cursor.fetchall()
    
    cursor.execute("SELECT keyword, searched_at FROM search_history WHERE customer_id = ? ORDER BY id DESC", (cust_id,))
    all_history = cursor.fetchall()
    
    # FPDF generation
    from fpdf import FPDF
    
    class PDF(FPDF):
        def header(self):
            # Title
            self.set_font('Helvetica', 'B', 15)
            self.cell(0, 10, 'Customer Search Intelligence Report', new_x='LMARGIN', new_y='NEXT', align='C')
            self.set_draw_color(111, 44, 244)
            self.set_line_width(0.5)
            self.line(10, 22, 200, 22)
            self.ln(10)
            
        def footer(self):
            # Page number
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()} | Generated by Mor Bazar Control Center', align='C')
            
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Helvetica', '', 10)
    
    # Customer Info Card
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Customer Details', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, f"Name: {user['name']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, f"Phone: {user['phone']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, f"Address: {user['address']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, f"Total Searches: {total_searches}", new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)
    
    # Top Searched Keywords Card
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Most Searched Keywords', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(100, 7, 'Keyword', border=1)
    pdf.cell(50, 7, 'Frequency', border=1, new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    
    for kw_row in top_keywords:
        pdf.cell(100, 7, kw_row['keyword'], border=1)
        pdf.cell(50, 7, str(kw_row['count']), border=1, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(8)
    
    # Complete Search History Section
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Complete Search History Log', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(100, 7, 'Keyword', border=1)
    pdf.cell(70, 7, 'Date & Time', border=1, new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    
    for hist_row in all_history:
        time_str = hist_row['searched_at']
        try:
            dt = datetime.strptime(hist_row['searched_at'], '%Y-%m-%d %H:%M:%S' if '.' not in hist_row['searched_at'] else '%Y-%m-%d %H:%M:%S.%f')
            time_str = dt.strftime('%d %b %Y %I:%M %p')
        except Exception:
            pass
        pdf.cell(100, 7, hist_row['keyword'], border=1)
        pdf.cell(70, 7, time_str, border=1, new_x='LMARGIN', new_y='NEXT')
        
    pdf_bytes = pdf.output()
    
    from flask import Response
    clean_name = "".join(c for c in user['name'] if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
    filename = f"Customer_Search_Report_{clean_name}.pdf"
    
    return Response(
        bytes(pdf_bytes),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route('/api/admin/database/export', methods=['GET'])
def export_database():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"hamar_bazar_backup_{timestamp}.db"
        return send_file(DB_PATH, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': f"Failed to export database: {str(e)}"}), 500

@app.route('/api/admin/database/import', methods=['POST'])
def import_database():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized.'}), 403
        
    if 'database_file' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
        
    file = request.files['database_file']
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
        
    if not file.filename.lower().endswith('.db'):
        return jsonify({'error': 'Invalid file format. Please upload a .db file.'}), 400
        
    # Read the first 16 bytes to verify it's a valid SQLite 3 database file
    header = file.read(16)
    if header != b'SQLite format 3\x00':
        return jsonify({'error': 'Invalid file content. The file is not a valid SQLite 3 database.'}), 400
        
    # Reset file pointer to the beginning
    file.seek(0)
    
    # Save the file temporarily
    temp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp_import.db')
    try:
        file.save(temp_path)
        
        # Connect to the source (uploaded file) and target (live file)
        src_conn = sqlite3.connect(temp_path)
        dest_conn = sqlite3.connect(DB_PATH)
        
        # Perform the backup operation
        src_conn.backup(dest_conn)
        
        src_conn.close()
        dest_conn.close()
        
        # Run migrations just in case
        run_migrations()
        
        # Remove the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        return jsonify({'success': True, 'message': 'Database restored successfully!'})
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        return jsonify({'error': f"Failed to restore database: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

