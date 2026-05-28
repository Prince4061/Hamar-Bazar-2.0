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
        password TEXT
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
        cooldown_until TIMESTAMP NULL
    )
    ''')
    
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
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id)
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
        ('Apna Bazaar (Kirana & General)', 'KIRANA', 5.0),
        ('The Bakers Table (Premium Cakes)', 'CAKES', 8.0),
        ('Fresh & Green Vegetables', 'VEGGIES', 4.0),
        ('ElectroWorld Solutions', 'ELECTRONICS', 10.0)
    ]
    for shop in shops_data:
        try:
            cursor.execute('INSERT INTO shops (shop_name, category, commission_pct) VALUES (?, ?, ?)', shop)
        except sqlite3.IntegrityError:
            pass # Already exists
            
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
        # Cakes
        (shop_ids['CAKES'], 'Chocolate Truffle Cake 500g', 450.0),
        (shop_ids['CAKES'], 'Red Velvet Cake 500g', 500.0),
        (shop_ids['CAKES'], 'Sparkling Candles Pack', 35.0),
        (shop_ids['CAKES'], 'Birthday Cap Premium', 25.0),
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
        (shop_ids['ELECTRONICS'], 'Smart WiFi Plug 16A', 599.0)
    ]
    
    for product in products_data:
        # Check if already seeded to avoid duplicates
        cursor.execute('SELECT id FROM products WHERE shop_id = ? AND name = ?', (product[0], product[1]))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO products (shop_id, name, price) VALUES (?, ?, ?)', product)
            
    # Seed Delivery Partners
    partners_data = [
        ('Rahul Rider', '9000000001', 0, 'online'),
        ('Amit Express', '9000000002', 0, 'online'),
        ('Vicky Speedster', '9000000003', 0, 'offline')
    ]
    for partner in partners_data:
        try:
            cursor.execute('INSERT INTO delivery_partners (name, phone, active_orders, availability_status) VALUES (?, ?, ?, ?)', partner)
        except sqlite3.IntegrityError:
            pass
            
    conn.commit()
    conn.close()
    print("Database seeded successfully with exclusive shops, products, users, and riders!")

if __name__ == '__main__':
    init_db()
    seed_db()
