# Hamar Bazar 2.0 - How to Run & Credentials

This guide explains how to run the application step-by-step and provides the seeded credentials to test all roles (Customer, Vendor, Delivery Rider, Admin).

---

## 🚀 How to Run the Project

The project runs on **Port 5001** (not the default 5000), which is why you might get a connection error if you try to open the default port. Follow these simple steps to run it:

### Option A: Double-Click the Starter Script (Recommended for Windows)
1. Navigate to the project folder `Hamar-Bazar-2.0`.
2. Double-click the [run.bat](file:///G:/Hamar%20Bazar/Hamar-Bazar-2.0/run.bat) file.
3. The script will:
   - Install required libraries (`Flask` and `fpdf2`).
   - Create and seed the local SQLite database (`marketplace.db`).
   - Open your browser automatically at **`http://127.0.0.1:5001`**.
   - Start the Flask server.

### Option B: Run Manually via Terminal
If you want to run it manually, execute these commands in your terminal or PowerShell inside the `Hamar-Bazar-2.0` directory:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Setup and seed the SQLite Database
python database.py

# 3. Run the application
python app.py
```
After starting, open your browser and go to: **[http://127.0.0.1:5001](http://127.0.0.1:5001)**

---

## 🔑 Test Credentials (Default Seeded Data)

All accounts use **`password123`** as the default password.

### 1. Customers (Grahak)
To log in as a customer on the `/login` page:
* **Alice Sharma**: Phone: `9876543210` | Password: `password123`
* **Bob Verma**: Phone: `8765432109` | Password: `password123`
* **Charlie Gupta**: Phone: `7654321098` | Password: `password123`
*(Note: Any new phone number will register a new customer account automatically on first login.)*

### 2. Vendors (Dukaan / Shop)
To log in as a vendor on the `/staff-login` page (Select **Vendor** role):
* **Apna Bazaar (Kirana)**: ID/Category: `KIRANA` | Password: `password123`
* **Apna Cakes & Bakery**: ID/Category: `CAKES` | Password: `password123`
* **Fresh & Green Vegetables**: ID/Category: `VEGGIES` | Password: `password123`
* **ElectroWorld (Electronics)**: ID/Category: `ELECTRONICS` | Password: `password123`
* **City Medicos (Pharmacy)**: ID/Category: `PHARMACY` | Password: `password123`
* **Hamar Tech Hub (Gadgets)**: ID/Category: `TECH` | Password: `password123`

### 3. Delivery Riders (Rider)
To log in as a delivery boy on the `/staff-login` page (Select **Delivery Boy** role):
* **Rahul Rider**: ID/Name: `Rahul Rider` or `1` | Password: `password123`
* **Amit Express**: ID/Name: `Amit Express` or `2` | Password: `password123`
* **Vicky Speedster**: ID/Name: `Vicky Speedster` or `3` | Password: `password123`

### 4. Super Admin (Control Center)
To log in as Admin on the `/staff-login` page (Select **Admin** role):
* **Admin**: ID/Username: `admin` | Password: `any_password` *(No strict password validation is required for the admin account; you can use any username/password)*
