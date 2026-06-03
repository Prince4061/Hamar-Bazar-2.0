import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'marketplace.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        address TEXT NOT NULL,
        profile_pic TEXT,
        password TEXT,
        is_blocked INTEGER DEFAULT 0,
        is_suspicious INTEGER DEFAULT 0,
        suspicion_reasons TEXT
    )
    ''')
    
    # Migration helpers for existing databases
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
    except sqlite3.OperationalError:
        pass # Already exists
        
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_suspicious INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN suspicion_reasons TEXT")
    except sqlite3.OperationalError:
        pass # Already exists
    
    # 2. Shops Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS shops (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shop_name TEXT NOT NULL,
        category TEXT UNIQUE NOT NULL,
        commission_pct REAL DEFAULT 5.0
    )
    ''')
    
    # 3. Products Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shop_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        is_available BOOLEAN DEFAULT 1,
        subcategory TEXT,
        description TEXT,
        image_path TEXT,
        FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE
    )
    ''')

    try:
        cursor.execute("ALTER TABLE products ADD COLUMN description TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE products ADD COLUMN image_path TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    # 4. Delivery Partners Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS delivery_partners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        active_orders INTEGER DEFAULT 0,
        availability_status TEXT DEFAULT 'online',
        cooldown_until TIMESTAMP NULL,
        password TEXT
    )
    ''')

    try:
        cursor.execute("ALTER TABLE delivery_partners ADD COLUMN password TEXT")
    except sqlite3.OperationalError:
        pass

    
    # 5. Orders Table (State Machine Master)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        shop_id INTEGER NOT NULL,
        delivery_boy_id INTEGER,
        total_amount REAL NOT NULL,
        gst_amount REAL DEFAULT 0.0,
        priority_type TEXT DEFAULT 'NORMAL',
        status TEXT DEFAULT 'PENDING',
        pickup_otp TEXT,
        delivery_otp TEXT,
        payment_mode TEXT DEFAULT 'COD',
        payment_screenshot TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        assigned_at TIMESTAMP,
        accepted_at TIMESTAMP,
        ready_at TIMESTAMP,
        delivered_at TIMESTAMP,
        failure_reason TEXT,
        FOREIGN KEY (customer_id) REFERENCES users(id),
        FOREIGN KEY (shop_id) REFERENCES shops(id),
        FOREIGN KEY (delivery_boy_id) REFERENCES delivery_partners(id)
    )
    ''')
    
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN payment_mode TEXT DEFAULT 'COD'")
    except sqlite3.OperationalError:
        pass # Already exists
        
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN payment_screenshot TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    # 6. Order Items Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id)
    )
    ''')
    
    # 7. Failed Logins Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS failed_logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL
    )
    ''')
    
    # Migrations for is_active in shops and image_path in products
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN image_path TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE products ADD COLUMN subcategory TEXT")
    except sqlite3.OperationalError:
        pass # Already exists
        
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN description TEXT")
    except sqlite3.OperationalError:
        pass # Already exists
        
    try:
        cursor.execute("ALTER TABLE shops ADD COLUMN is_active INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass # Already exists
        
    try:
        cursor.execute("ALTER TABLE shops ADD COLUMN password TEXT")
    except sqlite3.OperationalError:
        pass # Already exists

    try:
        cursor.execute("ALTER TABLE shops ADD COLUMN image_path TEXT")
    except sqlite3.OperationalError:
        pass # Already exists
        
    # 8. Prescription Requests Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS prescription_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        image_path TEXT NOT NULL,
        status TEXT DEFAULT 'PENDING',
        shop_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES users(id),
        FOREIGN KEY (shop_id) REFERENCES shops(id)
    )
    ''')
    
    # 9. Search History Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS search_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        keyword TEXT NOT NULL,
        searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')

    # 10. System Settings Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
        
    conn.commit()
    conn.close()
    print("Database tables created successfully!")

def seed_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Seed Users
    users_data = [
        ('Alice Sharma', '9876543210', 'Flat 101, Sunshine Apartments, Sector 4', 'password123'),
        ('Bob Verma', '8765432109', 'House 23, Green Valley Colony, Road 2', 'password123'),
        ('Charlie Gupta', '7654321098', 'Penthouse B, Skyline Heights, Main Road', 'password123')
    ]
    for user in users_data:
        try:
            cursor.execute('INSERT INTO users (name, phone, address, password) VALUES (?, ?, ?, ?)', user)
        except sqlite3.IntegrityError:
            # Update password for existing users to ensure they have the default password
            cursor.execute('UPDATE users SET password = ? WHERE phone = ?', ('password123', user[1]))
            
    # Seed Shops
    shops_data = [
        ('Apna Bazaar (Kirana & General)', 'KIRANA', 5.0, 'password123', '/static/images/grocery_basket.png'),
        ('Apna Cakes & Bakery', 'CAKES', 6.0, 'password123', '/static/images/cake_category.png'),
        ('Fresh & Green Vegetables', 'VEGGIES', 4.0, 'password123', '/static/images/veggies_category.png'),
        ('ElectroWorld Solutions', 'ELECTRONICS', 10.0, 'password123', '/static/images/electronics_category.png'),
        ('City Medicos & Pharmacy', 'PHARMACY', 7.0, 'password123', '/static/images/pharmacy_category.png'),
        ('Hamar Tech Hub (Gadgets & Accessories)', 'TECH', 8.0, 'password123', '/static/images/tech_category.png')
    ]
    for shop in shops_data:
        try:
            cursor.execute('INSERT INTO shops (shop_name, category, commission_pct, password, image_path) VALUES (?, ?, ?, ?, ?)', shop)
        except sqlite3.IntegrityError:
            cursor.execute('UPDATE shops SET shop_name = ?, password = ?, image_path = ? WHERE category = ?', (shop[0], shop[3], shop[4], shop[1]))
            
    conn.commit()
    
    # Fetch shop IDs for product mapping
    cursor.execute('SELECT id, category FROM shops')
    shop_ids = {row['category']: row['id'] for row in cursor.fetchall()}
    
    # Seed Products
    products_data = [
        # Kirana
        (shop_ids['KIRANA'], 'Amul Milk 1 Ltr', 62.0),
        (shop_ids['KIRANA'], 'Britannia Bread 400g', 35.0),
        (shop_ids['KIRANA'], 'Lays Classic 52g', 20.0),
        (shop_ids['KIRANA'], 'Amul Butter 100g', 55.0),
        (shop_ids['KIRANA'], 'Colgate Toothpaste 100g', 32.0),
        # Cakes & Bakery
        (shop_ids['CAKES'], 'Chocolate Truffle Cake 500g', 450.0),
        (shop_ids['CAKES'], 'Pineapple Cream Cake 500g', 350.0),
        (shop_ids['CAKES'], 'Fresh Fruit Cake 500g', 499.0),
        (shop_ids['CAKES'], 'Red Velvet Pastry 1pc', 80.0),
        (shop_ids['CAKES'], 'Vanilla Cupcake 1pc', 50.0),
        # Veggies
        (shop_ids['VEGGIES'], 'Potato 1kg', 30.0),
        (shop_ids['VEGGIES'], 'Tomato 1kg', 40.0),
        (shop_ids['VEGGIES'], 'Onion 1kg', 35.0),
        (shop_ids['VEGGIES'], 'Fresh Coriander Bundle', 12.0),
        (shop_ids['VEGGIES'], 'Fresh Lemon 250g', 25.0),
        # Electronics
        (shop_ids['ELECTRONICS'], 'Fast USB-C Cable 1.5m', 150.0),
        (shop_ids['ELECTRONICS'], 'Wired Earphones with Mic', 250.0),
        (shop_ids['ELECTRONICS'], 'AA Duracell Battery 4pc', 120.0),
        (shop_ids['ELECTRONICS'], 'Smart WiFi Plug 16A', 599.0),
        # Tech (Gadgets & Accessories)
        (shop_ids['TECH'], 'Wireless Bluetooth Earbuds', 999.0),
        (shop_ids['TECH'], 'Smart Fitness Tracker Smartwatch', 1499.0),
        (shop_ids['TECH'], 'Multi-Angle Phone Stand', 199.0),
        (shop_ids['TECH'], 'Rechargeable LED Desk Lamp', 499.0),
        # Pharmacy
        (shop_ids['PHARMACY'], 'Crocin Advance 500mg', 20.0, 'Pain Relief'),
        (shop_ids['PHARMACY'], 'Dolo 650mg', 30.0, 'Pain Relief'),
        (shop_ids['PHARMACY'], 'Combiflam Tablet 15pc', 45.0, 'Pain Relief'),
        (shop_ids['PHARMACY'], 'Vicks Vaporub 50g', 140.0, 'Cold & Cough'),
        (shop_ids['PHARMACY'], 'Cofsil Lozenges 10pc', 35.0, 'Cold & Cough'),
        (shop_ids['PHARMACY'], 'Benadryl Cough Syrup 100ml', 125.0, 'Cold & Cough'),
        (shop_ids['PHARMACY'], 'Limcee Vitamin C 15pc', 25.0, 'Vitamins'),
        (shop_ids['PHARMACY'], 'Revital H Capsules 10pc', 110.0, 'Vitamins'),
        (shop_ids['PHARMACY'], 'Calcium Sandoz 20pc', 160.0, 'Vitamins'),
        (shop_ids['PHARMACY'], 'Dettol Liquid 100ml', 60.0, 'First Aid'),
        (shop_ids['PHARMACY'], 'Band-Aid Premium 20pc', 45.0, 'First Aid'),
        (shop_ids['PHARMACY'], 'Betadine Ointment 15g', 95.0, 'First Aid'),
        (shop_ids['PHARMACY'], 'Dettol Hand Sanitizer 50ml', 25.0, 'Hygiene'),
        (shop_ids['PHARMACY'], 'Savlon Handwash 200ml', 85.0, 'Hygiene')
    ]
    
    for product in products_data:
        # Check if already seeded to avoid duplicates
        cursor.execute('SELECT id FROM products WHERE shop_id = ? AND name = ?', (product[0], product[1]))
        if not cursor.fetchone():
            subcat = product[3] if len(product) > 3 else None
            cursor.execute('INSERT INTO products (shop_id, name, price, subcategory) VALUES (?, ?, ?, ?)', (product[0], product[1], product[2], subcat))
            
    # Seed Delivery Partners
    partners_data = [
        ('Rahul Rider', '9000000001', 0, 'online', 'password123'),
        ('Amit Express', '9000000002', 0, 'online', 'password123'),
        ('Vicky Speedster', '9000000003', 0, 'offline', 'password123')
    ]
    for partner in partners_data:
        try:
            cursor.execute('INSERT INTO delivery_partners (name, phone, active_orders, availability_status, password) VALUES (?, ?, ?, ?, ?)', partner)
        except sqlite3.IntegrityError:
            cursor.execute('UPDATE delivery_partners SET password = ? WHERE phone = ?', ('password123', partner[1]))
            
    conn.commit()
    conn.close()
    print("Database seeded successfully with exclusive shops, products, users, and riders!")

def seed_historical_orders():
    import random
    from datetime import datetime, timedelta
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM orders")
    order_count = cursor.fetchone()[0]
    
    # If there are already a good number of orders, don't re-seed
    if order_count > 20:
        conn.close()
        print("Historical orders already seeded.")
        return
        
    cursor.execute("SELECT id FROM users")
    user_ids = [row['id'] for row in cursor.fetchall()]
    
    cursor.execute("SELECT id, category FROM shops")
    shops = cursor.fetchall()
    shop_ids = [row['id'] for row in shops]
    
    cursor.execute("SELECT id, shop_id, name, price FROM products")
    products_by_shop = {}
    for row in cursor.fetchall():
        s_id = row['shop_id']
        if s_id not in products_by_shop:
            products_by_shop[s_id] = []
        products_by_shop[s_id].append(dict(row))
        
    cursor.execute("SELECT id FROM delivery_partners")
    rider_ids = [row['id'] for row in cursor.fetchall()]
    
    if not user_ids or not shop_ids or not products_by_shop:
        print("Seeding failed: Users, shops, or products not found.")
        conn.close()
        return
        
    now = datetime.now()
    statuses = ['DELIVERED', 'DELIVERED', 'DELIVERED', 'DELIVERED', 'FAILED', 'DELIVERED']
    failure_reasons = ['Rider unavailable', 'Customer cancelled', 'Out of stock', 'Invalid address']
    
    print("Generating 80 historical orders for the last 7 days...")
    
    for i in range(80):
        hours_ago = random.randint(1, 168)
        created_dt = now - timedelta(hours=hours_ago)
        created_str = created_dt.strftime('%Y-%m-%d %H:%M:%S')
        
        cust_id = random.choice(user_ids)
        shop_id = random.choice(shop_ids)
        
        status = random.choice(statuses)
        if hours_ago <= 3:
            status = random.choice(['PENDING', 'ACCEPTED', 'READY_FOR_PICKUP', 'OUT_FOR_DELIVERY', 'DELIVERED'])
            
        priority = 'URGENT' if random.random() < 0.2 else 'NORMAL'
        
        sh_products = products_by_shop.get(shop_id, [])
        if not sh_products:
            continue
            
        num_items = random.randint(1, 3)
        order_items_to_add = random.sample(sh_products, min(num_items, len(sh_products)))
        
        total_amount = 0.0
        for prod in order_items_to_add:
            qty = random.randint(1, 2)
            total_amount += prod['price'] * qty
            
        fee = 15.0 if total_amount < 199.0 else 0.0
        total_amount += fee
        
        pickup_otp = f"{random.randint(1000, 9999)}"
        delivery_otp = f"{random.randint(1000, 9999)}"
        
        rider_id = None
        if status in ['ACCEPTED', 'READY_FOR_PICKUP', 'OUT_FOR_DELIVERY', 'DELIVERED']:
            rider_id = random.choice(rider_ids) if rider_ids else None
            
        accepted_at = None
        ready_at = None
        assigned_at = None
        delivered_at = None
        fail_reason = None
        
        if status != 'PENDING':
            accepted_at = (created_dt + timedelta(minutes=random.randint(2, 5))).strftime('%Y-%m-%d %H:%M:%S')
            
        if status in ['READY_FOR_PICKUP', 'OUT_FOR_DELIVERY', 'DELIVERED']:
            ready_at = (created_dt + timedelta(minutes=random.randint(7, 15))).strftime('%Y-%m-%d %H:%M:%S')
            
        if status in ['OUT_FOR_DELIVERY', 'DELIVERED']:
            assigned_at = (created_dt + timedelta(minutes=random.randint(8, 18))).strftime('%Y-%m-%d %H:%M:%S')
            
        if status == 'DELIVERED':
            delivered_at = (created_dt + timedelta(minutes=random.randint(18, 40))).strftime('%Y-%m-%d %H:%M:%S')
            
        if status == 'FAILED':
            fail_reason = random.choice(failure_reasons)
            
        cursor.execute('''
            INSERT INTO orders (customer_id, shop_id, delivery_boy_id, total_amount, gst_amount, priority_type, status, pickup_otp, delivery_otp, created_at, assigned_at, accepted_at, ready_at, delivered_at, failure_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cust_id, shop_id, rider_id, total_amount, 0.0, priority, status, pickup_otp, delivery_otp, created_str, assigned_at, accepted_at, ready_at, delivered_at, fail_reason))
        
        order_id = cursor.lastrowid
        
        for prod in order_items_to_add:
            qty = random.randint(1, 2)
            cursor.execute('''
                INSERT INTO order_items (order_id, product_id, quantity, price)
                VALUES (?, ?, ?, ?)
            ''', (order_id, prod['id'], qty, prod['price']))
            
    conn.commit()
    conn.close()
    print("Historical orders seeded successfully!")

def seed_search_history():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if we already have search records
    cursor.execute("SELECT COUNT(*) FROM search_history")
    count = cursor.fetchone()[0]
    if count > 0:
        conn.close()
        print("Search history already seeded.")
        return
        
    # We need user IDs. Let's fetch them.
    cursor.execute("SELECT id, name FROM users")
    users = {row['name']: row['id'] for row in cursor.fetchall()}
    
    # If no users, we can't seed search history
    if not users:
        conn.close()
        return
        
    import random
    from datetime import datetime, timedelta
    
    searches = []
    
    # Alice
    alice_id = users.get('Alice Sharma')
    if alice_id:
        alice_keywords = [
            ("cake", 24), ("chips", 15), ("chocolate cake", 8), 
            ("bread", 5), ("milk", 4), ("lays", 6), ("candles", 3)
        ]
        for kw, cnt in alice_keywords:
            for _ in range(cnt):
                hours_ago = random.randint(1, 120)
                searched_at = (datetime.now() - timedelta(hours=hours_ago)).strftime('%Y-%m-%d %H:%M:%S')
                searches.append((alice_id, kw, searched_at))
                
    # Bob
    bob_id = users.get('Bob Verma')
    if bob_id:
        bob_keywords = [
            ("milk", 12), ("bread", 10), ("butter", 8),
            ("potato", 4), ("onion", 6), ("dolo", 5)
        ]
        for kw, cnt in bob_keywords:
            for _ in range(cnt):
                hours_ago = random.randint(1, 120)
                searched_at = (datetime.now() - timedelta(hours=hours_ago)).strftime('%Y-%m-%d %H:%M:%S')
                searches.append((bob_id, kw, searched_at))
                
    # Charlie
    charlie_id = users.get('Charlie Gupta')
    if charlie_id:
        charlie_keywords = [
            ("crocin", 18), ("dolo", 12), ("cough syrup", 10),
            ("earphones", 5), ("battery", 6), ("wifi plug", 4)
        ]
        for kw, cnt in charlie_keywords:
            for _ in range(cnt):
                hours_ago = random.randint(1, 120)
                searched_at = (datetime.now() - timedelta(hours=hours_ago)).strftime('%Y-%m-%d %H:%M:%S')
                searches.append((charlie_id, kw, searched_at))
                
    cursor.executemany('INSERT INTO search_history (customer_id, keyword, searched_at) VALUES (?, ?, ?)', searches)
    conn.commit()
    conn.close()
    print("Search history seeded successfully!")

if __name__ == '__main__':
    init_db()
    seed_db()
    seed_historical_orders()
    seed_search_history()
