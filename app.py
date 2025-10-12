import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt, random, smtplib, ssl, datetime, jwt, re, threading, time
from functools import wraps
from bson.objectid import ObjectId
import os
import requests, certifi, traceback
import pickle

from PIL import Image

app = Flask(__name__)
CORS(app)

# ----------------- MongoDB Connection -----------------
client = MongoClient("mongodb+srv://ddarn3681:eyl349H2RkqaraZb@cluster0.ezhvpef.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["appfarmer"]
users_collection = db["users"]
works_collection = db["works"]  # new collection for posted works

SECRET_KEY = "yoursecretkey"

# ----------------- Helper Function to Send Email -----------------
def send_email(receiver_email, otp):
    try:
        smtp_server = "smtp.gmail.com"
        port = 465
        sender_email = "ajaiks2005@gmail.com"
        password = "ontj obmr ggeu kxeg"  

        message = f"""\
Subject: Your OTP Code
Content-Type: text/html

<html>
<body style="margin:0; font-family: Arial, sans-serif; background-color:#e0e0e0;">
    <div style="max-width:1200px; margin:auto;">
    <div style="background-color:#ffffff; text-align:center; padding:20px;">
        <h1 style="color:#E53935; margin:0; text-shadow:5px 2px 4px rgba(0,0,0,0.25);">
        HARIPASAGAV
        </h1>
    </div>
    <div style="background-color:#000; color:#ffffff; padding:20px 30px">
        <p style="font-size:18px; margin:10px 0px 10px 50px; color:#ffffff;">Hello,</p>
        <p style="font-size:18px; margin:10px 0px 10px 50px; color:#ffffff;">Your One-Time Password (OTP) is:</p>
        <h1 style="color:#E53935; font-size:42px; margin:20px 0; font-weight:bold; text-align:center;">
        {otp}
        </h1>
        <p style="font-size:16px;color:#ffffff; margin:0px 0px 10px 50px;">
        This OTP will expire in <strong>5 minutes</strong>. Please do not share it with anyone.
        </p>
        <p style="font-size:16px;color:#ffffff; margin-top:40px; text-align:center;">
        Thank you,<br/>
        <span style="color:#E53935; font-weight:bold;">HARIPASAGAV Team</span>
        </p>
    </div>
    </div>
</body>
</html>
"""
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

# ----------------- Email Validation -----------------
def is_valid_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)

# ----------------- Cleanup unverified users -----------------
def cleanup_unverified_users():
    while True:
        now = datetime.datetime.utcnow()
        try:
            result = users_collection.delete_many({"verified": False, "otp_expiry": {"$lt": now}})
            if result.deleted_count > 0:
                print(f"Deleted {result.deleted_count} unverified users due to expired OTP")
        except Exception as e:
            print("Cleanup error:", e)
        time.sleep(60)

threading.Thread(target=cleanup_unverified_users, daemon=True).start()

# ----------------- Register -----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers.get('Authorization')
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users_collection.find_one({
                "email": data.get("email"),
                "user_type": data.get("user_type")
            })
            if not current_user:
                return jsonify({"message": "User not found"}), 401
            kwargs['current_user'] = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except Exception as e:
            return jsonify({"message": "Token invalid", "error": str(e)}), 401

        return f(*args, **kwargs)
    return decorated

# ----------------- Register -----------------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        full_name = data.get('full_name')
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phone_number')
        user_type = data.get('user_type')

        if not all([full_name, username, email, password, phone_number, user_type]):
            return jsonify({"message": "All fields are required"}), 400

        if not is_valid_email(email):
            return jsonify({"message": "Invalid email format"}), 400

        if users_collection.find_one({"email": email, "user_type": user_type}):
            return jsonify({"message": "User already exists"}), 400

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        otp = str(random.randint(100000, 999999))
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

        users_collection.insert_one({
            "full_name": full_name,
            "username": username,
            "email": email,
            "password": hashed_pw,
            "phone_number": phone_number,
            "user_type": user_type,
            "verified": False,
            "otp": otp,
            "otp_expiry": expiry,
            "created_at": datetime.datetime.utcnow()
        })

        if send_email(email, otp):
            return jsonify({"message": "OTP sent to email. Please verify."}), 201
        else:
            return jsonify({"message": "User registered but failed to send OTP"}), 500
    except Exception as e:
        return jsonify({"message": "Error registering user", "error": str(e)}), 500

# ----------------- Verify OTP -----------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.json
        email = data.get('email')
        otp = data.get('otp')
        user_type = data.get('user_type')

        if not all([email, otp, user_type]):
            return jsonify({"message": "Email, OTP, and user_type required"}), 400

        user = users_collection.find_one({"email": email, "user_type": user_type})
        if not user:
            return jsonify({"message": "User not found"}), 404

        if user.get("otp") == otp and datetime.datetime.utcnow() < user.get("otp_expiry"):
            users_collection.update_one({"email": email, "user_type": user_type}, {"$set": {"verified": True}})
            token = jwt.encode({
                "email": email,
                "user_type": user_type,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }, SECRET_KEY, algorithm="HS256")
            return jsonify({"message": "OTP verified successfully", "token": token}), 200
        else:
            return jsonify({"message": "Invalid or expired OTP"}), 400

    except Exception as e:
        return jsonify({"message": "Error verifying OTP", "error": str(e)}), 500
# ----------------- Resend OTP -----------------
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    try:
        data = request.get_json(force=True)  # forces JSON parsing
        email = data.get('email')
        user_type = data.get('user_type')  # ✅ Added user_type
        otp_input = data.get('otp')  # OTP to verify (if provided)

        if not email or not user_type:
            return jsonify({"message": "Email and user_type are required"}), 400

        # ✅ Find user by both email and user_type
        user = users_collection.find_one({"email": email, "user_type": user_type})
        if not user:
            return jsonify({"message": f"{user_type.capitalize()} not found with this email"}), 404

        # ✅ If OTP is provided → verify it
        if otp_input:
            if user.get("otp") == otp_input and datetime.datetime.utcnow() < user.get("otp_expiry"):
                users_collection.update_one(
                    {"email": email, "user_type": user_type},
                    {"$set": {"verified": True}}
                )
                return jsonify({"message": f"{user_type.capitalize()} OTP verified successfully!"}), 200
            else:
                return jsonify({"message": "Invalid or expired OTP"}), 400

        # ✅ Otherwise → Generate and send new OTP
        otp = str(random.randint(100000, 999999))
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

        users_collection.update_one(
            {"email": email, "user_type": user_type},
            {"$set": {"otp": otp, "otp_expiry": expiry}}
        )

        if send_email(email, otp):
            return jsonify({"message": f"New OTP sent to {user_type}"}), 200
        else:
            return jsonify({"message": "Failed to send OTP"}), 500

    except Exception as e:
        return jsonify({"message": "Error resending OTP", "error": str(e)}), 500


# ----------------- Login -----------------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        user_type = data.get('user_type')

        if not email or not password or not user_type:
            return jsonify({"message": "All fields are required"}), 400

        user = users_collection.find_one({"email": email, "user_type": user_type})
        if not user:
            return jsonify({"message": "Invalid credentials"}), 400

        if not user.get("verified", False):
            return jsonify({"message": "Please verify your email with OTP"}), 403

        stored_pw = user.get('password')
        if isinstance(stored_pw, str):
            stored_pw = stored_pw.encode('utf-8')

        if bcrypt.checkpw(password.encode('utf-8'), stored_pw):
            token = jwt.encode({
                "email": email,
                "user_type": user_type, 
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }, SECRET_KEY, algorithm="HS256")
            return jsonify({"message": "Login successful", "token": token}), 200
        else:
            return jsonify({"message": "Incorrect password"}), 400

    except Exception as e:
        return jsonify({"message": "Error logging in", "error": str(e)}), 500

# ----------------- Token decorator -----------------
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         if 'Authorization' in request.headers:
#             auth_header = request.headers.get('Authorization')
#             if auth_header and auth_header.startswith("Bearer "):
#                 token = auth_header.split(" ")[1]

#         if not token:
#             return jsonify({"message": "Token is missing!"}), 401

#         try:
#             data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#             current_user = users_collection.find_one({
#                 "email": data.get("email"),
#                 "user_type": data.get("user_type")  # Match user_type from token
#             })
#             if not current_user:
#                 return jsonify({"message": "User not found"}), 401
#             kwargs['current_user'] = current_user
#         except jwt.ExpiredSignatureError:
#             return jsonify({"message": "Token expired"}), 401
#         except Exception as e:
#             return jsonify({"message": "Token is invalid", "error": str(e)}), 401

#         return f(*args, **kwargs)
#     return decorated


# ----------------- Add Work -----------------
@app.route('/add-work', methods=['POST'])
@token_required
def add_work(current_user):
    try:
        data = request.json
        title = data.get('title')
        description = data.get('description')
        location = data.get('location')
        payment = data.get('payment')

        if not title or not description or not location or payment is None:
            return jsonify({"message": "All fields required"}), 400

        try:
            payment_value = float(payment)
        except:
            return jsonify({"message": "Payment must be a number"}), 400

        work_doc = {
            "title": title,
            "description": description,
            "location": location,
            "payment": payment_value,
            "posted_by_email": current_user.get("email"),
            "posted_by_username": current_user.get("username"),
            "posted_by_user_type": current_user.get("user_type"),
            "created_at": datetime.datetime.utcnow(),
            "status": "open",
            "applied_workers": []  # array to store applied workers
        }

        result = works_collection.insert_one(work_doc)
        return jsonify({"message": "Work posted successfully", "work_id": str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({"message": "Error adding work", "error": str(e)}), 500

# ----------------- Get My Works -----------------
@app.route('/my-works', methods=['GET'])
@token_required
def my_works(current_user):
    try:
        email = current_user.get("email")
        cursor = works_collection.find({"posted_by_email": email}).sort("created_at", -1)
        works = []
        for w in cursor:
            works.append({
                "_id": str(w.get("_id")),
                "title": w.get("title"),
                "description": w.get("description"),
                "location": w.get("location"),
                "payment": w.get("payment"),
                "status": w.get("status"),
                "applied_workers": w.get("applied_workers", []),
                "created_at": w.get("created_at").isoformat() if w.get("created_at") else None
            })
        return jsonify({"works": works}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching works", "error": str(e)}), 500

# ----------------- Apply for Work -----------------
@app.route('/apply-work/<work_id>', methods=['POST'])
@token_required
def apply_work(current_user, work_id):
    try:
        work = works_collection.find_one({"_id": ObjectId(work_id)})
        if not work:
            return jsonify({"message": "Work not found"}), 404

        # Prevent farmer from applying to own work
        if current_user.get("email") == work.get("posted_by_email"):
            return jsonify({"message": "Cannot apply to your own work"}), 400

        # Check if already applied
        for w in work.get("applied_workers", []):
            if w["worker_email"] == current_user.get("email"):
                return jsonify({"message": "Already applied"}), 400

        works_collection.update_one(
            {"_id": ObjectId(work_id)},
            {"$push": {"applied_workers": {"worker_email": current_user.get("email"), "status": "Pending"}}}
        )
        return jsonify({"message": "Applied successfully"}), 200

    except Exception as e:
        return jsonify({"message": "Error applying to work", "error": str(e)}), 500

# ----------------- Approve Worker -----------------
@app.route('/approve-worker/<work_id>', methods=['POST'])
@token_required
def approve_worker(current_user, work_id):
    try:
        worker_email = request.json.get("worker_email")
        if not worker_email:
            return jsonify({"message": "Worker email required"}), 400

        work = works_collection.find_one({"_id": ObjectId(work_id)})
        if not work:
            return jsonify({"message": "Work not found"}), 404

        if work.get("posted_by_email") != current_user.get("email"):
            return jsonify({"message": "Not authorized"}), 403

        works_collection.update_one(
            {"_id": ObjectId(work_id), "applied_workers.worker_email": worker_email},
            {"$set": {"applied_workers.$.status": "Approved"}}
        )
        return jsonify({"message": "Worker approved"}), 200
    except Exception as e:
        return jsonify({"message": "Error approving worker", "error": str(e)}), 500

# ----------------- Worker Applied Works -----------------
@app.route('/applied-works', methods=['GET'])
@token_required
def applied_works(current_user):
    try:
        email = current_user.get("email")
        cursor = works_collection.find({"applied_workers.worker_email": email}).sort("created_at", -1)
        works = []
        for w in cursor:
            status = next((aw["status"] for aw in w.get("applied_workers", []) if aw["worker_email"] == email), "Pending")
            works.append({
                "_id": str(w.get("_id")),
                "title": w.get("title"),
                "description": w.get("description"),
                "location": w.get("location"),
                "payment": w.get("payment"),
                "status": status,
                "posted_by_email": w.get("posted_by_email"),
                "posted_by_username": w.get("posted_by_username")
            })
        return jsonify({"works": works}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching applied works", "error": str(e)}), 500

# ----------------- Cancel Application -----------------
@app.route('/cancel-application/<work_id>', methods=['POST'])
@token_required
def cancel_application(current_user, work_id):
    try:
        works_collection.update_one(
            {"_id": ObjectId(work_id)},
            {"$pull": {"applied_workers": {"worker_email": current_user.get("email")}}}
        )
        return jsonify({"message": "Application canceled"}), 200
    except Exception as e:
        return jsonify({"message": "Error canceling application", "error": str(e)}), 500

# ----------------- Get All Works (For Workers) -----------------
@app.route('/all-works', methods=['GET'])
@token_required
def all_works(current_user):
    try:
        cursor = works_collection.find().sort("created_at", -1)
        works = []
        for w in cursor:
            works.append({
                "_id": str(w.get("_id")),
                "title": w.get("title"),
                "description": w.get("description"),
                "location": w.get("location"),
                "payment": w.get("payment"),
                "status": w.get("status"),
                "posted_by_email": w.get("posted_by_email"),
                "applied_workers": w.get("applied_workers", []),
                "created_at": w.get("created_at").isoformat() if w.get("created_at") else None
            })
        return jsonify({"works": works}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching works", "error": str(e)}), 500


# ----------------- Get User Profile -----------------
@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        user_data = {
            "id": str(current_user.get("_id")),
            "fullname": current_user.get("full_name"),
            "username": current_user.get("username"),
            "email": current_user.get("email"),
            "phone": current_user.get("phone_number"),
            "user_type": current_user.get("user_type"),
            "verified": current_user.get("verified", False),
            "created_at": current_user.get("created_at").isoformat() if current_user.get("created_at") else None
        }
        return jsonify(user_data), 200
    except Exception as e:
        return jsonify({"message": "Error fetching profile", "error": str(e)}), 500

# ----------------- Add Product -----------------
@app.route('/add-product', methods=['POST'])
@token_required
def add_product(current_user):
    try:
        data = request.json
        product_name = data.get('product_name')
        description = data.get('description')
        price = data.get('price')
        email = data.get('email')
        phone = data.get('phone')
        bank_account = data.get('bank_account')
        location = data.get('location')
        image_url = data.get('image_url')

        if not all([product_name, description, price, email, phone, bank_account, location]):
            return jsonify({"message": "All fields are required"}), 400

        db.products.insert_one({
            "product_name": product_name,
            "description": description,
            "price": float(price),
            "email": email,
            "phone": phone,
            "bank_account": bank_account,
            "location": location,
            "image_url": image_url,
            "owner_email": current_user.get("email"),
            "created_at": datetime.datetime.utcnow()
        })

        return jsonify({"message": "Product added successfully"}), 201

    except Exception as e:
        return jsonify({"message": "Error adding product", "error": str(e)}), 500

@app.route('/my-products', methods=['GET'])
@token_required
def my_products(current_user):
    try:
        email = current_user.get("email")
        products = list(db.products.find({"owner_email": email}))
        for p in products:
            p["_id"] = str(p["_id"])
        return jsonify({"products": products}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching products", "error": str(e)}), 500

@app.route('/buyer-profile', methods=['GET'])
@token_required
def get_buyer_profile(current_user):
    try:
        # Ensure the user is a buyer
        if current_user.get('user_type') != 'buyer':
            return jsonify({'message': 'Unauthorized access!'}), 403

        profile_data = {
            'id': str(current_user.get('_id')),
            'full_name': current_user.get('full_name'),
            'username': current_user.get('username'),
            'email': current_user.get('email'),
            'phone_number': current_user.get('phone_number'),
            'user_type': current_user.get('user_type'),
            'verified': current_user.get('verified', False),
            'created_at': current_user.get('created_at').isoformat() if current_user.get('created_at') else None
        }
        return jsonify(profile_data), 200
    except Exception as e:
        return jsonify({"message": "Error fetching profile", "error": str(e)}), 500


# ----------------- Get All Products -----------------
@app.route('/all-products', methods=['GET'])
def get_all_products():
    try:
        products = list(db.products.find())
        for p in products:
            p['_id'] = str(p['_id'])
        return jsonify(products), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------- Add to Cart -----------------
@app.route('/add-to-cart', methods=['POST'])
@token_required
def add_to_cart(current_user):
    if current_user.get("user_type") != "buyer":
        return jsonify({"message": "Only buyers can add to cart"}), 403

    data = request.json
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))

    if not product_id:
        return jsonify({"message": "Product ID required"}), 400

    product = db.products.find_one({"_id": ObjectId(product_id)})
    if not product:
        return jsonify({"message": "Product not found"}), 404

    # Check if item already in cart
    cart_item = db.cart.find_one({"buyer_email": current_user.get("email"), "product_id": product_id})
    if cart_item:
        db.cart.update_one(
            {"_id": cart_item["_id"]},
            {"$inc": {"quantity": quantity}}
        )
    else:
        db.cart.insert_one({
            "buyer_email": current_user.get("email"),
            "product_id": product_id,
            "product_name": product["product_name"],
            "price": product["price"],
            "quantity": quantity,
            "added_at": datetime.datetime.utcnow()
        })

    return jsonify({"message": "Added to cart successfully"}), 201


# Save cart for a buyer


# Get cart
@app.route('/get-cart', methods=['GET'])
@token_required
def get_cart(current_user):
    if current_user.get("user_type") != "buyer":
        return jsonify({"message": "Unauthorized"}), 403

    items = list(db.cart.find({"buyer_email": current_user.get("email")}))
    for item in items:
        item["_id"] = str(item["_id"])
    return jsonify({"cart": items}), 200

# Update cart item quantity
@app.route('/update-cart', methods=['POST'])
@token_required
def update_cart(current_user):
    if current_user.get("user_type") != "buyer":
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))

    if not product_id:
        return jsonify({"message": "Product ID required"}), 400

    if quantity <= 0:
        db.cart.delete_one({"buyer_email": current_user.get("email"), "product_id": product_id})
        return jsonify({"message": "Item removed from cart"}), 200
    else:
        db.cart.update_one(
            {"buyer_email": current_user.get("email"), "product_id": product_id},
            {"$set": {"quantity": quantity}}
        )
        return jsonify({"message": "Cart updated"}), 200

# Remove from cart
@app.route('/remove-from-cart', methods=['POST'])
@token_required
def remove_from_cart(current_user):
    if current_user.get("user_type") != "buyer":
        return jsonify({"message": "Unauthorized"}), 403

    product_id = request.json.get("product_id")
    if not product_id:
        return jsonify({"message": "Product ID required"}), 400

    db.cart.delete_one({"buyer_email": current_user.get("email"), "product_id": product_id})
    return jsonify({"message": "Item removed from cart"}), 200

# Buy cart (checkout)
@app.route('/buy-cart', methods=['POST'])
@token_required
def buy_cart(current_user):
    if current_user.get("user_type") != "buyer":
        return jsonify({"message": "Unauthorized"}), 403

    cart_items = list(db.cart.find({"buyer_email": current_user.get("email")}))
    if not cart_items:
        return jsonify({"message": "Cart is empty"}), 400

    total = sum(item["price"] * item["quantity"] for item in cart_items)

    # Here you can also create an "orders" collection if you want to save order history
    for item in cart_items:
        db.orders.insert_one({
            "buyer_email": current_user.get("email"),
            "product_id": item["product_id"],
            "product_name": item["product_name"],
            "price": item["price"],
            "quantity": item["quantity"],
            "purchased_at": datetime.datetime.utcnow()
        })

    db.cart.delete_many({"buyer_email": current_user.get("email")})
    return jsonify({"message": f"Purchase successful, total: ₹{total}"}), 200



@app.route('/products', methods=['GET'])
def get_products():
    try:
        # Make sure this path points to your CSV file
        csv_path = os.path.join('assets', 'supplement_info.csv')

        if not os.path.exists(csv_path):
            return jsonify({'error': 'CSV file not found'}), 404

        # Read CSV
        df = pd.read_csv(csv_path)
        df = df.fillna('')  # Replace NaN with empty strings

        # Convert to list of dicts
        products = []
        for index, row in df.iterrows():
            products.append({
                'id': str(index),
                'disease': row.get('disease_name', ''),
                'supplement': row.get('supplement name', ''),
                'image': row.get('supplement image', ''),
                'link': row.get('buy link', '')
            })

        return jsonify(products)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

OPENROUTER_API_KEY = "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"

# Best model for agriculture chatbot
MODEL_ID = "mistralai/mistral-nemo"


def clean_output(text):
    """Clean model output while keeping paragraphs and bullets."""
    # Remove markdown * and ** but keep line breaks
    text = re.sub(r"\*+", "", text)
    # Convert markdown-style lists (- or •) to consistent bullets
    text = re.sub(r"(?m)^\s*[-•]\s*", "• ", text)
    # Add a new line before each bullet if missing
    text = re.sub(r"(?<!\n)(• )", r"\n\1", text)
    # Fix multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def clean_input(text):
    """Clean user input before sending to model."""
    text = re.sub(r"\*+", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def call_farmer_chatbot(user_message):
    """Send farmer's question to agricultural chatbot via OpenRouter."""
    system_prompt = (
        "You are KrishiBot, an intelligent agricultural assistant helping farmers. "
        "You give clear, practical advice in simple language about crops, soil, fertilizers, irrigation, "
        "pests, and modern farming. "
        "Your responses should be structured in short paragraphs or bullet points for clarity. "
        "If the question is not about farming, politely say you only answer agriculture-related topics."
    )

    user_message = clean_input(user_message)

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": MODEL_ID,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        "temperature": 0.6,
        "max_tokens": 700,
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        if "choices" in data and len(data["choices"]) > 0:
            raw_reply = data["choices"][0]["message"]["content"]
            formatted_reply = clean_output(raw_reply)
            return formatted_reply
        return "⚠️ Sorry, I couldn’t find an answer right now."
    except Exception as e:
        print("Error calling OpenRouter API:", e)
        return "⚠️ Server error while fetching chatbot response."


@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    user_message = data.get("message", "").strip()
    if not user_message:
        return jsonify({"error": "Message is required"}), 400

    reply = call_farmer_chatbot(user_message)
    return jsonify({"reply": reply, "model_used": MODEL_ID})


model_path = 'crop_recommendation_model.pkl'
with open(model_path, 'rb') as f:
    model = pickle.load(f)

@app.route('/predict', methods=['POST'])
def predict_crop():
    import numpy as np
    import torch
    import torch.nn as nn
    from torchvision.transforms.functional import to_tensor
    try:
        data = request.json
        # Extract features from request
        N = float(data['N'])
        P = float(data['P'])
        K = float(data['K'])
        temperature = float(data['temperature'])
        humidity = float(data['humidity'])
        ph = float(data['ph'])
        rainfall = float(data['rainfall'])
        
        features = np.array([[N, P, K, temperature, humidity, ph, rainfall]])
        prediction = model.predict(features)
        
        return jsonify({'predicted_crop': prediction[0]})
    except Exception as e:
        return jsonify({'error': str(e)})
    
    import torch
    import torch.nn as nn
#dsease
class PlantDiseaseModel(nn.Module):
    def __init__(self, num_classes=39):  # 39 instead of 38
        super().__init__()
        self.conv_layers = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(32),
            nn.Conv2d(32, 32, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(32),
            nn.MaxPool2d(2, 2),

            nn.Conv2d(32, 64, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(64),
            nn.Conv2d(64, 64, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(64),
            nn.MaxPool2d(2, 2),

            nn.Conv2d(64, 128, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(128),
            nn.Conv2d(128, 128, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(128),
            nn.MaxPool2d(2, 2),

            nn.Conv2d(128, 256, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(256),
            nn.Conv2d(256, 256, 3, padding=1),
            nn.ReLU(),
            nn.BatchNorm2d(256),
            nn.MaxPool2d(2, 2),
        )

        # Dense layers now match your saved weights
        self.dense_layers = nn.Sequential(
            nn.Flatten(),
            nn.Linear(256 * 14 * 14, 1024),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(1024, num_classes)  # Directly output 39 classes
        )

    def forward(self, x):
        x = self.conv_layers(x)
        x = self.dense_layers(x)
        return x


# --- Model setup ---
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
disease_model = PlantDiseaseModel(num_classes=39)
disease_model.load_state_dict(torch.load("plant_disease_model_1_latest.pt", map_location=device))
disease_model.to(device)
disease_model.eval()


# --- Predict function ---
def predict_disease(image_path):
    image = Image.open(image_path).convert("RGB").resize((224, 224))
    tensor = to_tensor(image).unsqueeze(0).to(device)
    with torch.inference_mode():
        output = disease_model(tensor)
        return int(output.cpu().numpy().argmax())


# --- Load CSVs ---
disease_df = pd.read_csv('assets/disease_info.csv').fillna('')
supplement_df = pd.read_csv('assets/supplement_info.csv').fillna('')


# --- Flask endpoint ---
@app.route("/aisubmit", methods=["POST"])
def aisubmit():
    if "image" not in request.files:
        return jsonify({"error": "No image"}), 400

    image = request.files["image"]
    if not image.filename:
        return jsonify({"error": "No file selected"}), 400

    os.makedirs("uploads", exist_ok=True)
    path = os.path.join("uploads", image.filename)
    image.save(path)

    try:
        idx = predict_disease(path)
        disease_data = disease_df.iloc[idx]
        supplement_data = supplement_df.iloc[idx]

        return jsonify({
            "pred": idx,
            "disease_name": disease_data.get("disease_name", ""),
            "description": disease_data.get("description", ""),
            "preventive_steps": disease_data.get("Possible Steps", ""),
            "disease_image": disease_data.get("image_url", ""),
            "supplement_name": supplement_data.get("supplement name", ""),
            "supplement_image": supplement_data.get("supplement image", ""),
            "buy_link": supplement_data.get("buy link", "")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
