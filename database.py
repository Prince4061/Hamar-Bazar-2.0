import sqlite3
import os
import shutil
from werkzeug.security import generate_password_hash

# Read SQLite environment parameters with defaults
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Check if test.db exists locally. If yes, default to test.db, else marketplace.db
default_db_name = 'test.db' if os.path.exists(os.path.join(BASE_DIR, 'test.db')) else 'marketplace.db'
DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, default_db_name))

# Ensure parent directory of database exists (critical for Docker volumes)
db_dir = os.path.dirname(DATABASE_PATH)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)

# Copy initial database from container root to persistent volume if target file doesn't exist
if not os.path.exists(DATABASE_PATH):
    source_local = os.path.join(BASE_DIR, default_db_name)
    if os.path.abspath(DATABASE_PATH) != os.path.abspath(source_local) and os.path.exists(source_local):
        print(f"[INFO] Copying {default_db_name} to volume path: {DATABASE_PATH}")
        try:
            shutil.copy2(source_local, DATABASE_PATH)
        except Exception as e:
            print(f"[ERROR] Failed to copy database to volume: {e}")

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, timeout=30.0)
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    # Enable Write-Ahead Logging (WAL) for better concurrent performance
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except sqlite3.OperationalError:
        pass
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
        suspicion_reasons TEXT,
        security_question TEXT,
        security_answer TEXT
    )
    ''')
    
    # Migrate existing databases by adding security columns if missing
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN security_question TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN security_answer TEXT")
    except sqlite3.OperationalError:
        pass
    
    # 2. Shops Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS shops (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shop_name TEXT NOT NULL,
        category TEXT UNIQUE NOT NULL,
        commission_pct REAL DEFAULT 5.0,
        is_active INTEGER DEFAULT 1,
        is_approved INTEGER DEFAULT 1,
        password TEXT,
        image_path TEXT,
        is_customizable INTEGER DEFAULT 0
    )
    ''')
    
    try:
        cursor.execute("ALTER TABLE shops ADD COLUMN is_approved INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    
    # 3. Products Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shop_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        mrp REAL,
        is_available BOOLEAN DEFAULT TRUE,
        subcategory TEXT,
        description TEXT,
        image_path TEXT,
        FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE CASCADE
    )
    ''')
    
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
    
    # 5. Orders Table
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
    
    # 6. Order Items Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        custom_text TEXT,
        custom_instructions TEXT,
        custom_image_path TEXT,
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
    
    # 7b. User Logins Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_phone TEXT NOT NULL,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
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
    
    # 11. Product Reviews Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS product_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        customer_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')

    # 12. Service Providers Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS service_providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        service_type TEXT NOT NULL,
        phone TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # 13. Service Reviews Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS service_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_id INTEGER NOT NULL,
        customer_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (provider_id) REFERENCES service_providers(id) ON DELETE CASCADE,
        FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')
    
    # Migrate products table by adding mrp column if missing
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN mrp REAL")
    except sqlite3.OperationalError:
        pass
        
    # Migrate order_items table by adding customization columns
    try:
        cursor.execute("ALTER TABLE order_items ADD COLUMN custom_text TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE order_items ADD COLUMN custom_instructions TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE order_items ADD COLUMN custom_image_path TEXT")
    except sqlite3.OperationalError:
        pass
        
    # Migrate shops table by adding is_customizable column if missing
    try:
        cursor.execute("ALTER TABLE shops ADD COLUMN is_customizable INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
        
    # Populate default customizable flags for seeded categories
    cursor.execute("UPDATE shops SET is_customizable = 1 WHERE category IN ('CAKES', 'TECH')")

    # Populate existing product mrp fields if null
    cursor.execute("UPDATE products SET mrp = ROUND(price * 1.25, 2) WHERE mrp IS NULL")

    # Create indexes for products table to optimize scaling and search speed (especially up to 100k+ products)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_shop_id ON products(shop_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_name ON products(name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_subcategory ON products(subcategory)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_products_is_available ON products(is_available)")

    # 14. Banners Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS banners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_url TEXT NOT NULL,
        product_id INTEGER,
        title TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    )
    ''')

    conn.commit()
    conn.close()
    print("SQLite database tables created successfully!")

def seed_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Seed banners if products already exist (for cases where DB is already seeded but banners table is empty)
    try:
        cursor.execute("SELECT COUNT(*) FROM products")
        if cursor.fetchone()[0] > 0:
            cursor.execute("SELECT COUNT(*) FROM banners")
            if cursor.fetchone()[0] == 0:
                banners_data = [
                    ('https://images.unsplash.com/photo-1578985545062-69928b1d9587?auto=format&fit=crop&w=1000&q=80', 6, 'Chocolate Truffle Cake - 20% OFF! 🎂'),
                    ('https://images.unsplash.com/photo-1563636619-e9143da7973b?auto=format&fit=crop&w=1000&q=80', 1, 'Fresh Amul Milk - Daily Essentials 🥛'),
                    ('https://images.unsplash.com/photo-1590658268037-6bf12165a8df?auto=format&fit=crop&w=1000&q=80', 20, 'Premium Wireless Earbuds - Flat 15% OFF! 🎧')
                ]
                for img, pid, title in banners_data:
                    cursor.execute("INSERT INTO banners (image_url, product_id, title, is_active) VALUES (?, ?, ?, 1)", (img, pid, title))
                conn.commit()
    except Exception as e:
        print("Pre-seed check for banners failed:", e)
        
    # Check if database is already seeded to optimize startup speed
    cursor.execute("SELECT COUNT(*) FROM shops")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return
    
    # Seed Users
    _hashed_user_pass = generate_password_hash('password123')
    users_data = [
        ('Alice Sharma', '9876543210', 'Flat 101, Sunshine Apartments, Sector 4', _hashed_user_pass, 'What is your favorite color?', 'blue'),
        ('Bob Verma', '8765432109', 'House 23, Green Valley Colony, Road 2', _hashed_user_pass, 'What is your childhood nickname?', 'bobby'),
        ('Charlie Gupta', '7654321098', 'Penthouse B, Skyline Heights, Main Road', _hashed_user_pass, 'In which city were you born?', 'delhi')
    ]
    for user in users_data:
        cursor.execute('''
            INSERT INTO users (name, phone, address, password, security_question, security_answer) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (phone) DO UPDATE SET password = EXCLUDED.password, security_question = EXCLUDED.security_question, security_answer = EXCLUDED.security_answer
        ''', (user[0], user[1], user[2], user[3], user[4], user[5]))
            
    # Seed Shops
    _hashed_shop_pass = generate_password_hash('password123')
    shops_data = [
        ('Apna Bazaar (Kirana & General)', 'KIRANA', 5.0, _hashed_shop_pass, '/static/images/grocery_basket.png'),
        ('Apna Cakes & Bakery', 'CAKES', 6.0, _hashed_shop_pass, '/static/images/cake_category.png'),
        ('Fresh & Green Vegetables', 'VEGGIES', 4.0, _hashed_shop_pass, '/static/images/veggies_category.png'),
        ('ElectroWorld Solutions', 'ELECTRONICS', 10.0, _hashed_shop_pass, '/static/images/electronics_category.png'),
        ('City Medicos & Pharmacy', 'PHARMACY', 7.0, _hashed_shop_pass, '/static/images/default_category.png'),
        ('Hamar Tech Hub (Gadgets & Accessories)', 'TECH', 8.0, _hashed_shop_pass, '/static/images/tech_category.png')
    ]
    for shop in shops_data:
        cursor.execute('''
            INSERT INTO shops (shop_name, category, commission_pct, password, image_path) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (category) DO UPDATE SET shop_name = EXCLUDED.shop_name, password = EXCLUDED.password, image_path = EXCLUDED.image_path
        ''', (shop[0], shop[1], shop[2], shop[3], shop[4]))
            
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
    
    PRODUCT_IMAGES = {
        # Kirana
        'Amul Milk 1 Ltr': 'https://images.unsplash.com/photo-1563636619-e9143da7973b?auto=format&fit=crop&w=300&q=80',
        'Britannia Bread 400g': 'https://images.unsplash.com/photo-1509440159596-0249088772ff?auto=format&fit=crop&w=300&q=80',
        'Lays Classic 52g': 'https://images.unsplash.com/photo-1566478989037-eec170784d0b?auto=format&fit=crop&w=300&q=80',
        'Amul Butter 100g': 'https://images.unsplash.com/photo-1589985270826-4b7bb135bc9d?auto=format&fit=crop&w=300&q=80',
        'Colgate Toothpaste 100g': 'https://images.unsplash.com/photo-1559599101-309004147615?auto=format&fit=crop&w=300&q=80',
        
        # Cakes & Bakery
        'Chocolate Truffle Cake 500g': 'https://images.unsplash.com/photo-1578985545062-69928b1d9587?auto=format&fit=crop&w=300&q=80',
        'Pineapple Cream Cake 500g': 'https://images.unsplash.com/photo-1588195538326-c5b1e9f8011b?auto=format&fit=crop&w=300&q=80',
        'Fresh Fruit Cake 500g': 'https://images.unsplash.com/photo-1535141192574-5d4897c13636?auto=format&fit=crop&w=300&q=80',
        'Red Velvet Pastry 1pc': 'https://images.unsplash.com/photo-1616541823729-00fe0aacd32c?auto=format&fit=crop&w=300&q=80',
        'Vanilla Cupcake 1pc': 'https://images.unsplash.com/photo-1576618148400-f54bed99fcfd?auto=format&fit=crop&w=300&q=80',
        
        # Veggies
        'Potato 1kg': 'https://images.unsplash.com/photo-1518977676601-b53f82aba655?auto=format&fit=crop&w=300&q=80',
        'Tomato 1kg': 'https://images.unsplash.com/photo-1595855759920-86582396756a?auto=format&fit=crop&w=300&q=80',
        'Onion 1kg': 'https://images.unsplash.com/photo-1508747703725-719ae257c26a?auto=format&fit=crop&w=300&q=80',
        'Fresh Coriander Bundle': 'https://images.unsplash.com/photo-1608797178974-15b35a61d121?auto=format&fit=crop&w=300&q=80',
        'Fresh Lemon 250g': 'https://images.unsplash.com/photo-1590502593747-42a996133562?auto=format&fit=crop&w=300&q=80',
        
        # Electronics
        'Fast USB-C Cable 1.5m': 'https://images.unsplash.com/photo-1541660724482-62a012f62bb7?auto=format&fit=crop&w=300&q=80',
        'Wired Earphones with Mic': 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80',
        'AA Duracell Battery 4pc': 'https://images.unsplash.com/photo-1595079676339-1534801ad6cf?auto=format&fit=crop&w=300&q=80',
        'Smart WiFi Plug 16A': 'https://images.unsplash.com/photo-1558002038-1055907df827?auto=format&fit=crop&w=300&q=80',
        
        # Tech
        'Wireless Bluetooth Earbuds': 'https://images.unsplash.com/photo-1590658268037-6bf12165a8df?auto=format&fit=crop&w=300&q=80',
        'Smart Fitness Tracker Smartwatch': 'https://images.unsplash.com/photo-1575311373937-040b8e1fd5b6?auto=format&fit=crop&w=300&q=80',
        'Multi-Angle Phone Stand': 'https://images.unsplash.com/photo-1616440347437-b1c73416efc2?auto=format&fit=crop&w=300&q=80',
        'Rechargeable LED Desk Lamp': 'https://images.unsplash.com/photo-1507473885765-e6ed057f782c?auto=format&fit=crop&w=300&q=80',
        
        # Pharmacy
        'Crocin Advance 500mg': 'https://images.unsplash.com/photo-1584017911766-d451b3d0e843?auto=format&fit=crop&w=300&q=80',
        'Dolo 650mg': 'https://images.unsplash.com/photo-1584017911766-d451b3d0e843?auto=format&fit=crop&w=300&q=80',
        'Combiflam Tablet 15pc': 'https://images.unsplash.com/photo-1584017911766-d451b3d0e843?auto=format&fit=crop&w=300&q=80',
        'Vicks Vaporub 50g': 'https://images.unsplash.com/photo-1607619056574-7b8d304b3b86?auto=format&fit=crop&w=300&q=80',
        'Cofsil Lozenges 10pc': 'https://images.unsplash.com/photo-1550572017-edd951b55104?auto=format&fit=crop&w=300&q=80',
        'Benadryl Cough Syrup 100ml': 'https://images.unsplash.com/photo-1550572017-edd951b55104?auto=format&fit=crop&w=300&q=80',
        'Limcee Vitamin C 15pc': 'https://images.unsplash.com/photo-1616671276441-2f2c277b8bf4?auto=format&fit=crop&w=300&q=80',
        'Revital H Capsules 10pc': 'https://images.unsplash.com/photo-1616671276441-2f2c277b8bf4?auto=format&fit=crop&w=300&q=80',
        'Calcium Sandoz 20pc': 'https://images.unsplash.com/photo-1616671276441-2f2c277b8bf4?auto=format&fit=crop&w=300&q=80',
        'Dettol Liquid 100ml': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?auto=format&fit=crop&w=300&q=80',
        'Band-Aid Premium 20pc': 'https://images.unsplash.com/photo-1603398938378-e54eab446dde?auto=format&fit=crop&w=300&q=80',
        'Betadine Ointment 15g': 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?auto=format&fit=crop&w=300&q=80',
        'Dettol Hand Sanitizer 50ml': 'https://images.unsplash.com/photo-1584622650111-993a426fbf0a?auto=format&fit=crop&w=300&q=80',
        'Savlon Handwash 200ml': 'https://images.unsplash.com/photo-1607006342411-91f11f04e8ac?auto=format&fit=crop&w=300&q=80',
    }

    for product in products_data:
        # Check if already seeded to avoid duplicates
        cursor.execute('SELECT id FROM products WHERE shop_id = ? AND name = ?', (product[0], product[1]))
        if not cursor.fetchone():
            subcat = product[3] if len(product) > 3 else None
            price = product[2]
            mrp = round(price * 1.25, 2)
            img_url = PRODUCT_IMAGES.get(product[1], None)
            cursor.execute('INSERT INTO products (shop_id, name, price, mrp, subcategory, image_path) VALUES (?, ?, ?, ?, ?, ?)', (product[0], product[1], price, mrp, subcat, img_url))
            
    # Seed Delivery Partners
    _hashed_rider_pass = generate_password_hash('password123')
    partners_data = [
        ('Rahul Rider', '9000000001', 0, 'online', _hashed_rider_pass),
        ('Amit Express', '9000000002', 0, 'online', _hashed_rider_pass),
        ('Vicky Speedster', '9000000003', 0, 'offline', _hashed_rider_pass)
    ]
    for partner in partners_data:
        cursor.execute('''
            INSERT INTO delivery_partners (name, phone, active_orders, availability_status, password) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (phone) DO UPDATE SET password = EXCLUDED.password
        ''', (partner[0], partner[1], partner[2], partner[3], partner[4]))
            
    # Seed system settings for delivery fee defaults and webhooks
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('delivery_fee_flat', '15.0')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('delivery_fee_threshold', '199.0')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('admin_qr_code', '/static/images/upi_qr_mockup.jpg')")
    cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('webhook_url', 'https://n8n.hamarai.in/webhook-test/167078e4-ccf5-4507-b605-fe218217f4b0')")
    cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('webhook_enabled', '1')")
    cursor.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('webhook_events', 'order_created,user_search,status_changed,stock_alert,user_flagged')")

    
    # Seed some product reviews (Check if already seeded to avoid duplicates)
    cursor.execute("SELECT COUNT(*) FROM product_reviews")
    reviews_count = cursor.fetchone()[0]
    if reviews_count == 0:
        # We need product IDs and customer IDs.
        # Alice (id=1), Bob (id=2), Charlie (id=3)
        # Let's seed for Amul Milk (id=1)
        cursor.execute("INSERT INTO product_reviews (product_id, customer_id, rating, comment) VALUES (1, 1, 5, 'Very fresh and good quality milk!')")
        cursor.execute("INSERT INTO product_reviews (product_id, customer_id, rating, comment) VALUES (1, 2, 4, 'Always delivered cold. Recommended.')")
        # Chocolate Truffle Cake (id=6)
        cursor.execute("INSERT INTO product_reviews (product_id, customer_id, rating, comment) VALUES (6, 3, 5, 'Best chocolate cake in town! Super soft and tasty.')")
        # Potato (id=11)
        cursor.execute("INSERT INTO product_reviews (product_id, customer_id, rating, comment) VALUES (11, 1, 4, 'Aloo fresh the aur size bhi accha tha.')")
        # Wireless bluetooth earbuds (id=20)
        cursor.execute("INSERT INTO product_reviews (product_id, customer_id, rating, comment) VALUES (20, 2, 5, 'Value for money product, sound quality is great.')")

    # Seed Service Providers
    cursor.execute("SELECT COUNT(*) FROM service_providers")
    sp_count = cursor.fetchone()[0]
    if sp_count == 0:
        sp_data = [
            ('Ramesh Kumar', 'Plumber', '9876543211', 'leakage repair, pipe fittings, tap repair and installation with 5 years experience'),
            ('Amit Singh', 'Electrician', '9876543212', 'complete house wiring, fan installation, switchboard repair, appliance troubleshooting'),
            ('Sonu Verma', 'Carpenter', '9876543213', 'sofa making, wooden door installations, cupboard repairs, wooden furniture polishing'),
            ('Ravi Yadav', 'Plumber', '9876543214', 'drainage blockage cleaning, kitchen sink fittings, water tank cleaning services'),
            ('Manoj Sen', 'Electrician', '9876543215', 'inverter installation, geyser installation, light fittings, short circuit fixing')
        ]
        for name, s_type, phone, desc in sp_data:
            cursor.execute("INSERT INTO service_providers (name, service_type, phone, description) VALUES (?, ?, ?, ?)", (name, s_type, phone, desc))
            
        # Seed Service Reviews (Alice = 1, Bob = 2, Charlie = 3)
        cursor.execute("INSERT INTO service_reviews (provider_id, customer_id, rating, comment) VALUES (1, 1, 5, 'Ramesh did an excellent job. Quick and highly professional!')")
        cursor.execute("INSERT INTO service_reviews (provider_id, customer_id, rating, comment) VALUES (1, 2, 4, 'Punctual and resolved our pipeline leakage quickly.')")
        cursor.execute("INSERT INTO service_reviews (provider_id, customer_id, rating, comment) VALUES (2, 3, 5, 'Amit is a very knowledgeable electrician. Recommended!')")
        cursor.execute("INSERT INTO service_reviews (provider_id, customer_id, rating, comment) VALUES (3, 1, 4, 'Sonu fixed my wooden door lock perfectly.')")

    # Seed banners if empty (for fresh database runs)
    cursor.execute("SELECT COUNT(*) FROM banners")
    if cursor.fetchone()[0] == 0:
        banners_data = [
            ('https://images.unsplash.com/photo-1578985545062-69928b1d9587?auto=format&fit=crop&w=1000&q=80', 6, 'Chocolate Truffle Cake - 20% OFF! 🎂'),
            ('https://images.unsplash.com/photo-1563636619-e9143da7973b?auto=format&fit=crop&w=1000&q=80', 1, 'Fresh Amul Milk - Daily Essentials 🥛'),
            ('https://images.unsplash.com/photo-1590658268037-6bf12165a8df?auto=format&fit=crop&w=1000&q=80', 20, 'Premium Wireless Earbuds - Flat 15% OFF! 🎧')
        ]
        for img, pid, title in banners_data:
            cursor.execute("INSERT INTO banners (image_url, product_id, title, is_active) VALUES (?, ?, ?, 1)", (img, pid, title))

    conn.commit()
    conn.close()
    print("Database seeded successfully with exclusive shops, products, users, riders, services, and system settings!")

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
