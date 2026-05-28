from flask import Flask, render_template, request, jsonify, redirect, session, g
import sqlite3
import os
import random
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'hyperlocal_monopolistic_secret_key_12345'
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'marketplace.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# -------------------------------------------------------------
# Role Switcher & Mock Session
# -------------------------------------------------------------
@app.route('/session/switch')
def switch_session():
    role = request.args.get('role', 'customer')
    role_id = request.args.get('id', '1')
    
    session['role'] = role
    session['role_id'] = int(role_id)
    
    # Store additional names in session for UI greeting
    db = get_db()
    cursor = db.cursor()
    if role == 'customer':
        cursor.execute("SELECT name FROM users WHERE id = ?", (role_id,))
        row = cursor.fetchone()
        session['name'] = row['name'] if row else 'Customer'
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
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE phone LIKE ? OR name LIKE ?", (f"%{phone}%", f"%{username}%"))
        user = cursor.fetchone()
        
        if user:
            session['role'] = 'customer'
            session['role_id'] = user['id']
            session['name'] = user['name']
            return jsonify({'success': True, 'redirect': '/customer'})
        else:
            # Dynamically register/create a new customer if phone number doesn't exist
            # This implements "anyone can login by their credentials"
            new_address = "Sector 4, Local Area"
            try:
                cursor.execute("INSERT INTO users (name, phone, address) VALUES (?, ?, ?)", (username, phone, new_address))
                db.commit()
                # Get the newly created user
                cursor.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,))
                user = cursor.fetchone()
                session['role'] = 'customer'
                session['role_id'] = user['id']
                session['name'] = user['name']
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
        
        if not role or not identifier:
            return jsonify({'success': False, 'error': 'Role and ID are required.'})
            
        db = get_db()
        cursor = db.cursor()
        
        if role == 'admin':
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

            # Check if vendor identifier exists
            shop = None
            if identifier.isdigit():
                cursor.execute("SELECT * FROM shops WHERE id = ?", (int(identifier),))
                shop = cursor.fetchone()
            else:
                cursor.execute("SELECT * FROM shops WHERE shop_name LIKE ? OR category LIKE ?", (f"%{identifier}%", f"%{identifier}%"))
                shop = cursor.fetchone()
                
            if not shop:
                # If shop doesn't exist, dynamically create it to let anyone log in!
                category = "SHOP_" + identifier.upper().replace(" ", "_")[:10]
                shop_name = identifier if "shop" in identifier.lower() or "bazaar" in identifier.lower() else f"{identifier} Store"
                try:
                    cursor.execute("INSERT INTO shops (shop_name, category, commission_pct) VALUES (?, ?, ?)", (shop_name, category, 5.0))
                    db.commit()
                    cursor.execute("SELECT * FROM shops WHERE id = ?", (cursor.lastrowid,))
                    shop = cursor.fetchone()
                    
                    # Seed default products
                    cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop['id'], 'Standard Product A', 100.0))
                    cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop['id'], 'Standard Product B', 200.0))
                    cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop['id'], 'Standard Product C', 350.0))
                    db.commit()
                except Exception as e:
                    # Check if category exists
                    cursor.execute("SELECT * FROM shops WHERE category = ?", (category,))
                    shop = cursor.fetchone()
                    if not shop:
                        return jsonify({'success': False, 'error': f'Failed to create vendor: {str(e)}'})
            
            session['role'] = 'vendor'
            session['role_id'] = shop['id']
            session['name'] = shop['shop_name']
            return jsonify({'success': True, 'redirect': '/vendor'})
            
        elif role == 'delivery':
            # Normalize common delivery boy aliases to seeded riders
            norm_id = identifier.lower().strip()
            if norm_id in ['rahul', 'rahul rider', 'rider1', '1']:
                identifier = 'Rahul Rider'
            elif norm_id in ['amit', 'amit express', 'rider2', '2']:
                identifier = 'Amit Express'
            elif norm_id in ['vicky', 'vicky speedster', 'rider3', '3']:
                identifier = 'Vicky Speedster'

            rider = None
            if identifier.isdigit():
                cursor.execute("SELECT * FROM delivery_partners WHERE id = ?", (int(identifier),))
                rider = cursor.fetchone()
            else:
                cursor.execute("SELECT * FROM delivery_partners WHERE name LIKE ?", (f"%{identifier}%",))
                rider = cursor.fetchone()
                
            if not rider:
                rider_name = identifier if "rider" in identifier.lower() or "delivery" in identifier.lower() else f"{identifier} Rider"
                import random
                mock_phone = f"9000{random.randint(100000, 999999)}"
                try:
                    cursor.execute("INSERT INTO delivery_partners (name, phone, active_orders, availability_status) VALUES (?, ?, 0, 'online')", (rider_name, mock_phone))
                    db.commit()
                    cursor.execute("SELECT * FROM delivery_partners WHERE id = ?", (cursor.lastrowid,))
                    rider = cursor.fetchone()
                except Exception as e:
                    return jsonify({'success': False, 'error': f'Failed to create rider: {str(e)}'})
                    
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
    cursor.execute("SELECT * FROM shops")
    shops = [dict(row) for row in cursor.fetchall()]
    return jsonify(shops)

@app.route('/api/shops/<int:shop_id>/products', methods=['GET'])
def get_shop_products(shop_id):
    db = get_db()
    cursor = db.cursor()
    # If request is from vendor view, show all. If customer, show only available.
    is_vendor = request.args.get('view_type') == 'vendor'
    if is_vendor:
        cursor.execute("SELECT * FROM products WHERE shop_id = ?", (shop_id,))
    else:
        cursor.execute("SELECT * FROM products WHERE shop_id = ? AND is_available = 1", (shop_id,))
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
        
    db = get_db()
    cursor = db.cursor()
    
    # Calculate Total Amount & GST
    total_amount = 0.0
    products_details = []
    
    for item in items:
        prod_id = item['product_id']
        qty = int(item['quantity'])
        cursor.execute("SELECT price, name FROM products WHERE id = ? AND shop_id = ?", (prod_id, shop_id))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({'error': f'Product {prod_id} not found in this shop.'}), 400
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
    
    # Generate OTPs (4 digits numeric)
    pickup_otp = f"{random.randint(1000, 9999)}"
    delivery_otp = f"{random.randint(1000, 9999)}"
    
    # Insert Order Master record
    cursor.execute('''
        INSERT INTO orders (customer_id, shop_id, total_amount, gst_amount, priority_type, status, pickup_otp, delivery_otp)
        VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
    ''', (customer_id, shop_id, grand_total, gst_amount, priority_type, pickup_otp, delivery_otp))
    
    order_id = cursor.lastrowid
    
    # Insert Order Items
    for pd in products_details:
        cursor.execute('''
            INSERT INTO order_items (order_id, product_id, quantity, price)
            VALUES (?, ?, ?, ?)
        ''', (order_id, pd['product_id'], pd['quantity'], pd['price']))
        
    db.commit()
    
    return jsonify({
        'message': 'Order placed successfully!',
        'order_id': order_id,
        'pickup_otp': pickup_otp, # Kept for debugging/testing visibility if needed
        'delivery_otp': delivery_otp
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

# --- Vendor APIs ---

@app.route('/api/vendor/orders/<int:shop_id>', methods=['GET'])
def get_vendor_orders(shop_id):
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
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
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
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT status, pickup_otp FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
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
    data = request.json
    product_id = data.get('product_id')
    is_available = data.get('is_available')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE products SET is_available = ? WHERE id = ?", (is_available, product_id))
    db.commit()
    return jsonify({'message': 'Product availability updated.'})

@app.route('/api/vendor/low-stock-prediction/<int:shop_id>', methods=['GET'])
def get_low_stock_prediction(shop_id):
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
    data = request.json
    rider_id = data.get('delivery_boy_id')
    
    if not rider_id:
        return jsonify({'error': 'Delivery Rider ID is required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    # 1. Check Cooldown
    cursor.execute("SELECT cooldown_until FROM delivery_partners WHERE id = ?", (rider_id,))
    rider = cursor.fetchone()
    if not rider:
        return jsonify({'error': 'Rider not found.'}), 404
        
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
    data = request.json
    entered_otp = data.get('otp')
    rider_id = data.get('delivery_boy_id')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT pickup_otp, status, delivery_boy_id FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
    if order['delivery_boy_id'] != rider_id:
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
    data = request.json
    entered_otp = data.get('otp')
    rider_id = data.get('delivery_boy_id')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT delivery_otp, status, delivery_boy_id FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    
    if not order:
        return jsonify({'error': 'Order not found.'}), 404
    if order['delivery_boy_id'] != rider_id:
        return jsonify({'error': 'This order is not assigned to you.'}), 403
    if order['status'] != 'OUT_FOR_DELIVERY':
        return jsonify({'error': 'Order status must be OUT FOR DELIVERY.'}), 400
        
    if order['delivery_otp'] == entered_otp:
        cursor.execute("UPDATE orders SET status = 'DELIVERED', delivered_at = CURRENT_TIMESTAMP WHERE id = ?", (order_id,))
        cursor.execute("UPDATE delivery_partners SET active_orders = MAX(0, active_orders - 1) WHERE id = ?", (rider_id,))
        db.commit()
        return jsonify({'message': 'Delivery OTP verified! Order successfully DELIVERED.'})
    else:
        return jsonify({'error': 'Invalid Delivery OTP. Please verify with Customer.'}), 400

# --- Admin APIs ---

@app.route('/api/admin/analytics', methods=['GET'])
def get_admin_analytics():
    db = get_db()
    cursor = db.cursor()
    
    # 1. High level aggregate stats
    cursor.execute("SELECT COUNT(id) FROM orders WHERE status = 'DELIVERED'")
    delivered_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(id) FROM orders WHERE status = 'FAILED' OR failure_reason IS NOT NULL")
    failed_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT SUM(total_amount) FROM orders WHERE status = 'DELIVERED'")
    total_rev = cursor.fetchone()[0] or 0.0
    
    cursor.execute("SELECT SUM(total_amount * (SELECT commission_pct FROM shops s WHERE s.id = orders.shop_id) / 100.0) FROM orders WHERE status = 'DELIVERED'")
    total_comm = cursor.fetchone()[0] or 0.0
    
    # 2. Shop-wise sales & ratings (Vendor Reputation Score, INT-010, ADMIN-001)
    cursor.execute('''
        SELECT s.id as shop_id, s.shop_name, s.category,
               COUNT(o.id) as total_orders,
               SUM(CASE WHEN o.status = 'DELIVERED' THEN o.total_amount ELSE 0 END) as sales,
               SUM(CASE WHEN o.status = 'DELIVERED' THEN 1 ELSE 0 END) as success_orders,
               SUM(CASE WHEN o.status = 'FAILED' OR o.failure_reason IS NOT NULL THEN 1 ELSE 0 END) as failed_orders
        FROM shops s
        LEFT JOIN orders o ON s.id = o.shop_id
        GROUP BY s.id
    ''')
    shops_performance = [dict(row) for row in cursor.fetchall()]
    
    # Calculate performance scores for each vendor (Acceptance rates, etc.)
    for sp in shops_performance:
        tot = sp['total_orders']
        sp['acceptance_rate'] = round((sp['success_orders'] / tot * 100), 1) if tot > 0 else 100.0
        # Dummy mock satisfaction scores
        sp['avg_rating'] = round(random.uniform(4.2, 4.9), 1) if sp['success_orders'] > 0 else 5.0
        
    # 3. Peak order hours (Heatmap visual, INT-006, ADMIN-001)
    cursor.execute('''
        SELECT STRFTIME('%H', created_at) as hour, COUNT(id) as count
        FROM orders
        GROUP BY hour
        ORDER BY hour ASC
    ''')
    peak_times = {row['hour']: row['count'] for row in cursor.fetchall()}
    # Ensure all 24 hours have entries
    for h in range(24):
        h_str = f"{h:02d}"
        if h_str not in peak_times:
            peak_times[h_str] = 0
            
    # 4. Top Selling Products
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
    
    # 5. Order list for Admin details
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
    
    return jsonify({
        'overview': {
            'delivered_count': delivered_count,
            'failed_count': failed_count,
            'total_revenue': round(total_rev, 2),
            'total_commission': round(total_comm, 2)
        },
        'shops_performance': shops_performance,
        'peak_times': peak_times,
        'top_products': top_products,
        'recent_orders': recent_orders
    })

@app.route('/api/admin/products', methods=['POST'])
def admin_add_product():
    data = request.json
    shop_id = data.get('shop_id')
    name = data.get('name')
    price = data.get('price')
    
    if not shop_id or not name or price is None:
        return jsonify({'error': 'Parameters shop_id, name, and price are required.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)", (shop_id, name, float(price)))
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
        
        cursor.execute('''
            UPDATE products 
            SET name = ?, price = ?, is_available = ? 
            WHERE id = ?
        ''', (name, float(price), int(is_available), prod_id))
        db.commit()
        return jsonify({'message': 'Product updated successfully.'})

# --- Rider Active Job & Status APIs ---
@app.route('/api/delivery/rider/<int:rider_id>/active', methods=['GET'])
def get_rider_active_order(rider_id):
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
