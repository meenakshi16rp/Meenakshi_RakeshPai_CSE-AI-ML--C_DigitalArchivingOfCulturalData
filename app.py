from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, g, send_file
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pymongo import PyMongo
import gridfs
from werkzeug.utils import secure_filename
from bson import ObjectId
from io import BytesIO
from collections import defaultdict
from datetime import datetime,timedelta
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore, auth
import re
import json
import math
from together import Together
import os
import tempfile
import base64

# Initialize the app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

bcrypt = Bcrypt(app)

# Initialize Firebase Admin SDK
# Make sure your serviceAccountKey.json is in the same directory as app.py
try:
    cred = credentials.Certificate("serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")
    # Handle the error appropriately, perhaps exit or disable auth features

@app.route('/')
def home():
    return render_template('main.html')

@app.route('/aboutus')
def about():
    return render_template('aboutus.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        try:
            # Create Firebase user
            user = auth.create_user(email=email, password=password)

            # Set display name (optional)
            auth.update_user(user.uid, display_name=fullname)

            # Automatically assign admin role to specific emails
            # Make sure to change these emails to your actual admin emails
            admin_emails = ["meenakshi16rp@gmail.com", "otheradmin@domain.com"]
            if email in admin_emails:
                auth.set_custom_user_claims(user.uid, {"role": "admin"})

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('signin'))

        except Exception as e:
            flash(f"Error creating account: {str(e)}", "danger")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # Firebase Admin SDK does not have a direct password check for security reasons
            # You would typically handle sign-in on the frontend using Firebase Authentication SDK
            # and then verify the ID token on the backend using the /sessionLogin route.
            # For this example, we'll simulate getting user info by email.
            user = auth.get_user_by_email(email)

            # Get the user's role from custom claims
            claims = user.custom_claims if user.custom_claims else {}
            role = claims.get("role", "user")  # Default to 'user' if no role exists

            # Store minimal user info and role in session
            session['user_id'] = user.uid # Store UID
            session['email'] = user.email
            session['fullname'] = user.display_name # Store display name
            session['user_role'] = role

            flash("Login successful. Redirecting...", "success")

            # Redirect based on role
            if role == "admin":
                return redirect(url_for('admin_dashboard'))
            else:
                # Redirect regular users to the upload page
                return redirect(url_for('upload_page'))

        except firebase_admin.auth.UserNotFoundError:
             flash("Login failed: User not found.", "danger")
             return redirect(url_for('signin'))
        except Exception as e:
            flash(f"Login failed: {str(e)}", "danger")
            return redirect(url_for('signin'))

    return render_template('signin.html')

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form['email']
    try:
        # Firebase sends a reset link to the user's email
        auth.generate_password_reset_link(email)
        flash("Password reset instructions have been sent to your email.", "success")
    except firebase_admin.auth.UserNotFoundError:
        flash("Email not found, please try again.", "danger")
    except Exception as e:
        flash(f"Error sending password reset email: {str(e)}", "danger")

    return redirect(url_for('signin'))

@app.route('/logout')
def logout():
    session.clear() # Clear the Flask session
    flash("You have been logged out.", "success")
    return redirect(url_for('home'))

# This route is typically called from the frontend after Firebase client-side sign-in
# to establish a backend session.
@app.route('/sessionLogin', methods=['POST'])
def session_login():
    data = request.get_json()
    id_token = data.get('idToken')

    if not id_token:
        return jsonify({"error": "ID token not provided"}), 400

    try:
        # Verify the ID token while checking if the token is revoked.
        decoded_token = auth.verify_id_token(id_token, check_revoked=True)

        # Token is valid and not revoked. Get the user's UID and other claims.
        uid = decoded_token['uid']
        email = decoded_token.get('email')
        # Retrieve user to get display name and custom claims
        user = auth.get_user(uid)
        role = user.custom_claims.get('role', 'user') if user.custom_claims else 'user'


        # Store essential information in the Flask session
        session['user_id'] = uid
        session['email'] = email
        session['fullname'] = user.display_name # Store display name
        session['user_role'] = role # Store the role from custom claims

        # Set a global variable 'g' for easy access in the current request context
        g.user = {
            "uid": uid,
            "email": email,
            "fullname": user.display_name,
            "role": role
        }


        return jsonify({"message": "Session set successfully", "role": role}), 200

    except firebase_admin.auth.InvalidIdTokenError:
        return jsonify({"error": "Invalid ID token"}), 401
    except firebase_admin.auth.ExpiredIdTokenError:
        return jsonify({"error": "Expired ID token"}), 401
    except firebase_admin.auth.RevokedIdTokenError:
         return jsonify({"error": "ID token has been revoked"}), 401
    except Exception as e:
        print(f"Error verifying ID token: {e}")
        return jsonify({"error": f"Failed to set session: {str(e)}"}), 500


# Decorator to protect routes, requiring a valid session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user_id is in session
        if 'user_id' not in session:
            # Optionally, verify the Firebase token again if not in session (more secure but slower)
            # This depends on your frontend's session management (e.g., using ID tokens)
            # For simplicity here, we rely on session state after sessionLogin
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('signin'))

        # Load user info into global context 'g' if not already there
        if not hasattr(g, 'user'):
             try:
                 user = auth.get_user(session['user_id'])
                 g.user = {
                    "uid": user.uid,
                    "email": user.email,
                    "fullname": user.display_name,
                    "role": user.custom_claims.get('role', 'user') if user.custom_claims else 'user'
                 }
             except Exception as e:
                 print(f"Error loading user info for g: {e}")
                 flash("Error loading user information. Please log in again.", "danger")
                 session.clear()
                 return redirect(url_for('signin'))


        return f(*args, **kwargs)
    return decorated_function

# Decorator to require admin role
def admin_required(f):
    @wraps(f)
    @login_required # Ensure user is logged in first
    def decorated_function(*args, **kwargs):
        if g.user.get('role') != 'admin':
            flash("Access Denied: Admins Only!", "danger")
            return redirect(url_for('home')) # Redirect to a non-admin page
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin_dashboard')
@admin_required # Protect the admin dashboard route
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Get all users (Admin only)
@app.route('/admin/users', methods=['GET']) # Protected route
@admin_required
def get_all_users():
    try:
        # Fetch users from Firebase Auth
        users = auth.list_users().iterate_all()

        user_list = []
        for user in users:
            # Ensure claims exist before accessing
            claims = user.custom_claims if user.custom_claims else {}
            role = claims.get("role", "user")  # Default role is "user"

            user_list.append({
                "uid": user.uid,
                "email": user.email,
                "fullname": user.display_name if user.display_name else "N/A",
                "role": role,
                "disabled": user.disabled, # Include disabled status
                "creation_time": user.user_metadata.creation_timestamp # Include creation time
            })

        return jsonify(user_list)
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({"error": f"Failed to fetch users: {str(e)}"}), 500


# Assign role to user (Admin only)
@app.route('/admin/assign_role/<uid>', methods=['POST']) # Protected route
@admin_required
def assign_role(uid):
    try:
        role = request.json.get("role")
        if role not in ["admin", "user"]:
            return jsonify({"error": "Invalid role specified"}), 400

        # Set custom user claims in Firebase Auth
        auth.set_custom_user_claims(uid, {"role": role})

        # Force refresh of the user's token on their next request
        # This ensures the new role claim is picked up promptly
        auth.revoke_refresh_tokens(uid)

        return jsonify({"message": f"Role updated successfully for user {uid} to {role}. User will need to log in again."})
    except firebase_admin.auth.UserNotFoundError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"Error assigning role: {e}")
        return jsonify({"error": f"Failed to assign role: {str(e)}"}), 500


# Delete user (Admin only)
@app.route('/admin/delete_user/<uid>', methods=['DELETE']) # Protected route
@admin_required
def delete_user(uid):
    try:
        # Delete user from Firebase Auth
        auth.delete_user(uid)

        # Optional: Delete user's files from MongoDB/GridFS
        # This requires adding a user_id field when saving files
        # mongo.db['fs.files'].delete_many({"userId": uid}) # Assuming 'userId' field exists

        return jsonify({"message": "User deleted successfully"})
    except firebase_admin.auth.UserNotFoundError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({"error": f"Failed to delete user: {str(e)}"}), 500


# Configure MongoDB
app.config["MONGO_URI"] = "mongodb+srv://divanshityagi21:5Ogy1brCYcuwXcJx@clustertest.pnkoi.mongodb.net/digitalarchiving" # Replace with your MongoDB URI
mongo = PyMongo(app)
fs = gridfs.GridFS(mongo.db) # Initialize GridFS instance

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "avi", "mov", "pdf", "txt", "html", "css", "js", "json"} # Added more text/code file types


def allowed_file(filename):
    """Check if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for analyzing image metadata (used by the upload page)
# This route does NOT require admin_required as regular users can upload
@app.route("/analyze-image", methods=["POST"])
@login_required
def analyze_image():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed for analysis"}), 400

    # Save temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file.filename.rsplit('.', 1)[1].lower()}") as temp_file:
        file.save(temp_file.name)
        temp_filename = temp_file.name

    image_base64 = None
    try:
        if file.content_type.startswith("image/"):
            with open(temp_filename, "rb") as image_file:
                image_bytes = image_file.read()
                image_base64 = base64.b64encode(image_bytes).decode()
        else:
            return jsonify({ "title": "", "description": "" })

    except Exception as e:
        print(f"Error processing image file: {e}")
        try: os.unlink(temp_filename)
        except OSError as os_error: print(f"Temp cleanup failed: {os_error}")
        return jsonify({"error": f"Image processing error: {str(e)}"}), 500

    prompt = """
Respond with a JSON object only. Do not include extra text.
Return two keys: "title" and "description".

Example format:
{
  "title": "Bharatanatyam Dance",
  "description": "Bharatanatyam is a classical Indian dance form originating from Tamil Nadu..."
}

Context: The image depicts Indian cultural heritage—monuments, dances, art, or historical people. Write concisely (title) and descriptively (100-150 words).
"""

    response_text = ""
    ai_analysis_successful = False

    try:
        from together import Together
        client = Together(api_key="51df07beb081982c5b1a919b3f91662e2a5b322211ec358b79bc7135d914fede")

        response = client.chat.completions.create(
            model="meta-llama/Llama-Vision-Free",
            messages=[
                {"role": "user", "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_base64}"}}
                ]}
            ],
            max_tokens=300,
            temperature=0.7,
            top_p=0.7,
            top_k=50,
            repetition_penalty=1,
            stream=False
        )
        response_text = response.choices[0].message.content.strip()
        print("Raw AI response:\n", response_text)  # Debug log
        ai_analysis_successful = True

    except Exception as e:
        print(f"AI error: {e}")
        ai_analysis_successful = False

    finally:
        try: os.unlink(temp_filename)
        except OSError as os_error: print(f"Cleanup failed: {os_error}")

    # Try to parse AI response as JSON
    try:
        if ai_analysis_successful:
            result = json.loads(response_text)
            result['ai_generated'] = True
            return jsonify(result)
    except json.JSONDecodeError:
        print("AI output is not valid JSON.")

    # Fallback extraction using regex
    title = "Unknown"
    description = response_text

    title_match = re.search(r'Title\s*[:\-]?\s*(.*)', response_text, re.IGNORECASE)
    desc_match = re.search(r'Description\s*[:\-]?\s*([\s\S]+)', response_text, re.IGNORECASE)

    if title_match:
        title = title_match.group(1).strip()
    if desc_match:
        description = desc_match.group(1).strip()

    return jsonify({
        "title": title,
        "description": description,
        "ai_generated": ai_analysis_successful
    })

# Handle file upload with metadata
@app.route('/files/post', methods=['POST'])
@login_required # Require login to upload files
def upload_with_metadata():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    filename = secure_filename(file.filename)

    # Get metadata from the form (these fields are sent from upload.html)
    metadata = {
        "title": request.form.get("title", "Untitled"),
        "description": request.form.get("description", "No description provided"),
        "date": request.form.get("date"), # Should be formatted date string
        "language": request.form.get("language", ""),
        "state": request.form.get("state", ""),
        # "user" field from frontend is ignored, use backend session info
        "category": request.form.get("category", "other"),
        "tags": [tag.strip() for tag in request.form.get("tags", "").split(',') if tag.strip()], # Split comma-separated tags into a list
        "ai_generated": request.form.get("ai_generated", 'false').lower() == 'true' # Get AI analysis status from form
    }

    # Add backend-controlled metadata
    metadata["uploaded_by"] = {
        "uid": g.user['uid'], # Use UID from session
        "email": g.user['email'],
        "fullname": g.user['fullname']
    }
    metadata["upload_date"] = datetime.utcnow() # Use backend timestamp
    metadata["content_type"] = file.content_type

    try:
        # Save the file to GridFS with the collected metadata
        file_id = fs.put(file, filename=filename, **metadata)

        # Note: The original `metadata` dict is passed using `**metadata` unpacking
        # This saves all key-value pairs directly as GridFS extra attributes.
        # If you want to store metadata under a specific 'metadata' sub-document,
        # you would adjust this: fs.put(file, filename=filename, metadata=metadata_dict)
        # The current frontend expects metadata at the top level of the GridFS file object.


        return jsonify({"message": "File uploaded successfully", "file_id": str(file_id)}), 201

    except Exception as e:
        print(f"Error saving file to GridFS: {e}")
        return jsonify({"error": f"Failed to upload file: {str(e)}"}), 500


@app.route('/files/download/<file_id>', methods=['GET'])
# @login_required # Consider if file downloads should require login
def download_file(file_id):
    try:
        # Retrieve the file from GridFS
        file = fs.get(ObjectId(file_id))

        # Send the file data
        # as_attachment=True prompts download, False displays in browser
        return send_file(BytesIO(file.read()), mimetype=file.content_type, as_attachment=True, download_name=file.filename)
    except gridfs.NoFile:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        print(f"Error downloading file {file_id}: {e}")
        return jsonify({"error": f"Failed to download file: {str(e)}"}), 500


@app.route('/files/delete/<file_id>', methods=['DELETE'])
@login_required # Require login to delete files
# @admin_required # Consider if only admins should delete, or allow users to delete their own
def delete_file(file_id):
    try:
        # Optional: Add logic here to check if the logged-in user has permission to delete this file
        # e.g., check if g.user['uid'] matches the 'uploaded_by.uid' in the file's metadata
        file_meta = mongo.db['fs.files'].find_one({"_id": ObjectId(file_id)}, {"uploaded_by.uid": 1})
        if file_meta and 'uploaded_by' in file_meta and file_meta['uploaded_by'].get('uid') != g.user.get('uid') and g.user.get('role') != 'admin':
             return jsonify({"error": "You do not have permission to delete this file"}), 403


        # Delete the file from GridFS
        fs.delete(ObjectId(file_id))
        return jsonify({"message": "File deleted successfully"}), 200
    except gridfs.NoFile:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        print(f"Error deleting file {file_id}: {e}")
        return jsonify({"error": f"Failed to delete file: {str(e)}"}), 500


# Admin route to get all files with filtering and pagination
@app.route('/admin/all_files', methods=['GET'])
@admin_required # Protect this route
def admin_list_files():
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 15, type=int) # Number of items per page
        search_term = request.args.get('search', '').strip()
        category_filter = request.args.get('category', '').strip()
        date_from_str = request.args.get('date_from', '').strip()
        date_to_str = request.args.get('date_to', '').strip()
        user_uid_filter = request.args.get('user_uid', '').strip() # Added filter for user UID

        # Build query based on filters
        query = {}
        if search_term:
            # Use regex for case-insensitive search across multiple fields
            search_regex = re.compile(search_term, re.IGNORECASE)
            query['$or'] = [
                {'filename': search_regex},
                {'title': search_regex},
                {'description': search_regex},
                {'tags': search_regex}, # Assuming tags are stored as strings or array of strings
                {'uploaded_by.email': search_regex}, # Search by uploader email
                {'uploaded_by.fullname': search_regex} # Search by uploader name
            ]
        if category_filter:
            query['category'] = category_filter
        if date_from_str or date_to_str:
            query['upload_date'] = {}
            if date_from_str:
                try:
                    date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
                    query['upload_date']['$gte'] = date_from
                except ValueError:
                    return jsonify({"error": "Invalid date_from format. Use YYYY-MM-DD."}), 400
            if date_to_str:
                try:
                    # End of the day for 'date_to'
                    date_to = datetime.strptime(date_to_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59, microsecond=999999)
                    query['upload_date']['$lte'] = date_to
                except ValueError:
                    return jsonify({"error": "Invalid date_to format. Use YYYY-MM-DD."}), 400

        # Apply user UID filter if provided
        if user_uid_filter:
            query['uploaded_by.uid'] = user_uid_filter


        # Get total number of files matching the query for pagination
        total_files = mongo.db['fs.files'].count_documents(query)

        # Calculate skip and limit for pagination
        skip = (page - 1) * limit
        if skip < 0: skip = 0 # Ensure skip is not negative

        # Fetch files with sorting (e.g., by upload date descending)
        # Also project only necessary fields for the dashboard list
        files_cursor = mongo.db['fs.files'].find(query, {
            "_id": 1, "filename": 1, "length": 1, "uploadDate": 1,
            "title": 1, "description": 1, "category": 1, "tags": 1,
            "uploaded_by": 1, "ai_generated": 1, "contentType": 1, "upload_date": 1 # Use the new field names
        }).sort("upload_date", -1).skip(skip).limit(limit) # Sort by the correct date field


        file_list = []
        for file in files_cursor:
            file_list.append({
                "file_id": str(file["_id"]),
                "filename": file.get("filename", "N/A"),
                "size_bytes": file.get("length"), # 'length' is the default size field in GridFS
                "upload_date": file.get("upload_date").isoformat() if file.get("upload_date") else None, # Use the new field name and format
                "title": file.get("title"),
                "description": file.get("description"),
                "category": file.get("category"),
                "tags": file.get("tags", []),
                "uploaded_by": file.get("uploaded_by"), # Includes uid, email, fullname
                "ai_generated": file.get("ai_generated", False), # Default to False if not present
                "content_type": file.get("contentType")
            })

        return jsonify({
            "files": file_list,
            "total_files": total_files,
            "page": page,
            "limit": limit,
            "total_pages": math.ceil(total_files / limit) if limit > 0 else 0
        }), 200

    except Exception as e:
        print(f"Error fetching all files for admin: {e}")
        return jsonify({"error": f"Failed to fetch files: {str(e)}"}), 500


# Route to get session info (can be used by frontend for display)
@app.route('/sessionInfo', methods=['GET'])
# @login_required # Consider if session info requires login
def session_info():
    # If login_required decorator is used, g.user will be available
    if hasattr(g, 'user') and g.user:
        return jsonify({
            "uid": g.user.get('uid'),
            "email": g.user.get('email'),
            "fullname": g.user.get('fullname'),
            "role": g.user.get('role')
        })
    # If not using login_required here, check session directly (less secure if session isn't fully validated)
    if 'user_id' in session:
         try:
             user = auth.get_user(session['user_id'])
             return jsonify({
                "uid": user.uid,
                "email": user.email,
                "fullname": user.display_name,
                "role": user.custom_claims.get('role', 'user') if user.custom_claims else 'user'
             })
         except Exception as e:
             print(f"Error retrieving user info from session: {e}")
             # Clear session if user cannot be retrieved
             session.clear()
             return jsonify({"error": "Session user not found, please log in again"}), 401

    return jsonify({"error": "Not logged in"}), 401


@app.route('/file/preview/<file_id>', methods=['GET'])
# @login_required # Consider if file previews should require login
def preview_file(file_id):
    try:
        # Retrieve the file from GridFS
        file = fs.get(ObjectId(file_id))

        # For text files, you might want to read and return text
        # For others, return as file data
        if file.content_type and file.content_type.startswith('text/'):
             return file.read().decode('utf-8'), 200, {'Content-Type': 'text/plain; charset=utf-8'} # Return as plain text
        elif file.content_type == 'application/json':
             # Attempt to pretty print JSON
             try:
                 json_obj = json.load(file)
                 return json.dumps(json_obj, indent=2), 200, {'Content-Type': 'application/json'}
             except Exception:
                 # If not valid JSON, return as plain text
                 return file.read().decode('utf-8'), 200, {'Content-Type': 'text/plain; charset=utf-8'}

        # For other file types (image, video, pdf), send as file data
        return send_file(BytesIO(file.read()), mimetype=file.content_type)
    except gridfs.NoFile:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        print(f"Error previewing file {file_id}: {e}")
        return jsonify({"error": f"Failed to preview file: {str(e)}"}), 500

# Admin route to edit file metadata
@app.route('/admin/edit_file/<file_id>', methods=['PUT'])
@admin_required # Protect this route
def admin_edit_file_metadata(file_id):
    try:
        updates = request.json # Get updates from JSON body

        # Define allowed fields that can be updated
        allowed_fields = ["title", "description", "category", "language", "state", "tags"]

        # Build update dictionary with only allowed fields
        update_doc = {}
        for field in allowed_fields:
            if field in updates:
                # Special handling for tags: ensure it's a list
                if field == "tags":
                     # Assume tags are sent as a comma-separated string and convert to list
                     if isinstance(updates[field], str):
                         update_doc[field] = [tag.strip() for tag in updates[field].split(',') if tag.strip()]
                     elif isinstance(updates[field], list):
                          update_doc[field] = updates[field] # Allow list directly
                     else:
                         # Ignore if format is unexpected
                         print(f"Warning: Received tags in unexpected format for file {file_id}: {updates[field]}")
                         pass
                else:
                    update_doc[field] = updates[field]

        if not update_doc:
             return jsonify({"message": "No valid fields provided for update"}), 200 # Or 400


        # Update the metadata fields in the GridFS files collection
        result = mongo.db['fs.files'].update_one(
            {"_id": ObjectId(file_id)},
            {"$set": update_doc}
        )

        if result.matched_count == 0:
            return jsonify({"error": "File not found"}), 404
        elif result.modified_count > 0:
            return jsonify({"message": "File metadata updated successfully"}), 200
        else:
            return jsonify({"message": "File metadata matched but no changes were made"}), 200


    except Exception as e:
        print(f"Error updating file metadata for {file_id}: {e}")
        return jsonify({"error": f"Failed to update file metadata: {str(e)}"}), 500


# Admin route for analytics summary
@app.route('/admin/analytics/summary', methods=['GET'])
@admin_required # Protect this route
def analytics_summary():
    try:
        # Get total users from Firebase Auth
        total_users = 0
        try:
            for user in auth.list_users().iterate_all():
                total_users += 1
        except Exception as user_list_error:
            print(f"Error listing Firebase users for summary: {user_list_error}") # Added more specific log
            total_users = "Error" # Indicate error fetching user count


        try:
            total_files = mongo.db['fs.files'].count_documents({})
        except Exception as mongo_count_error:
             print(f"Error counting files in MongoDB for summary: {mongo_count_error}") # Added more specific log
             total_files = "Error" # Indicate error fetching file count

        # Get recent uploads (e.g., last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        try:
            recent_uploads_last_7_days = mongo.db['fs.files'].count_documents({"upload_date": {"$gte": seven_days_ago}})
        except Exception as recent_uploads_error:
            print(f"Error counting recent uploads in MongoDB for summary: {recent_uploads_error}") # Added more specific log
            recent_uploads_last_7_days = "Error"

        # Get file category distribution
        # Use aggregation pipeline to group by category and count
        category_distribution = {}
        try:
            category_distribution_cursor = mongo.db['fs.files'].aggregate([
                {"$group": {"_id": "$category", "count": {"$sum": 1}}},
                {"$project": {"_id": 0, "category": "$_id", "count": 1}} # Reshape output
            ])
            category_distribution = {item['category'] if item['category'] else 'Unknown': item['count'] for item in category_distribution_cursor}

        except Exception as category_error:
             print(f"Error getting category distribution from MongoDB for summary: {category_error}") # Added more specific log
             category_distribution = {"Error": 0}

        # TODO: Implement storage usage calculation if needed
        storage_used = "N/A" # Placeholder


        return jsonify({
            "total_users": total_users,
            "total_files": total_files,
            "recent_uploads_last_7_days": recent_uploads_last_7_days,
            "category_distribution": category_distribution,
            "storage_used": storage_used
        }), 200

    except Exception as e:
        print(f"Generic error generating analytics summary: {e}") # Added more specific log
        return jsonify({"error": f"Failed to load analytics summary: {str(e)}"}), 500

# Admin route for uploads over time analytics
@app.route('/admin/analytics/uploads_over_time', methods=['GET'])
@admin_required # Protect this route
def uploads_over_time():
    try:
        # Get uploads with upload date and user ID (if available)
        # Ensure upload_date is indexed for better performance on large datasets
        uploads_cursor = mongo.db['fs.files'].find({}, {"upload_date": 1, "uploaded_by.uid": 1}) # Use the new field names

        # Group data by date and optionally by user
        upload_counts = defaultdict(lambda: defaultdict(int))
        all_dates = set()

        for upload in uploads_cursor:
            date = upload.get("upload_date")
            user_id = upload.get("uploaded_by", {}).get("uid", "unknown") # Default to 'unknown' user

            if isinstance(date, datetime):
                date_str = date.date().isoformat() # Format date as YYYY-MM-DD
                upload_counts[user_id][date_str] += 1
                all_dates.add(date_str)
            else:
                # Log files with invalid or missing date
                print(f"Warning: File with ID {upload.get('_id')} has invalid or missing upload_date: {date}")


        # Get sorted dates
        sorted_dates = sorted(list(all_dates))

        # Prepare data for Chart.js
        datasets = []

        # Fetch user full names/emails for labels
        user_info = {}
        user_ids_in_data = list(upload_counts.keys())
        if 'unknown' in user_ids_in_data: user_ids_in_data.remove('unknown')

        if user_ids_in_data:
             try:
                 # Fetch user records in batches if there are many users
                 # Max allowed UIDs in auth.get_users is 100
                 batch_size = 99
                 for i in range(0, len(user_ids_in_data), batch_size):
                     batch_uids = user_ids_in_data[i:i+batch_size]
                     # Ensure batch_uids is not empty before calling auth.get_users
                     if batch_uids:
                         for user_record in auth.get_users(batch_uids).users:
                             user_info[user_record.uid] = user_record.display_name if user_record.display_name else user_record.email
             except Exception as e:
                 print(f"Error fetching user info for uploads over time chart labels: {e}") # Added more specific log
                 # Proceed without user names if fetching fails


        # Generate random colors for charts
        def get_random_color(index, total):
             if total == 0: return 'rgb(100, 100, 100)' # Default color if no data
             hue = (index * 137.508) % 360 # Golden Angle approximation for distinct hues
             return f"hsl({hue}, 70%, 60%)"


        # Create a dataset for each user (or 'unknown')
        for i, (user_id, date_data) in enumerate(upload_counts.items()):
            data = [date_data.get(date, 0) for date in sorted_dates]
            label = user_info.get(user_id, user_id) # Use name/email or UID/unknown
            color = get_random_color(i, len(upload_counts)) # Assign a unique color

            datasets.append({
                "label": label,
                "data": data,
                "borderColor": color,
                "backgroundColor": color + '40', # Add some transparency for fill
                "fill": False, # Set to true for area chart
                "tension": 0.1 # Add some curve to lines
            })

        return jsonify({
            "labels": sorted_dates,
            "datasets": datasets
        }), 200

    except Exception as e:
        print(f"Generic error generating uploads over time data: {e}") # Added more specific log
        return jsonify({"error": f"Failed to load uploads over time data: {str(e)}"}), 500


# Route to get session info (can be used by frontend for display)
# @app.route('/sessionInfo') # Already defined above
# def session_info():
#    ... # Existing code

# Route to list files (used by the regular gallery)
# @app.route('/files/list', methods=['GET']) # Already defined above
# def list_files():
#     ... # Existing code


# Update the upload_page route if needed (e.g., to require login)
@app.route('/upload')
@login_required # Require login to access the upload page
def upload_page():
    return render_template('upload.html')

@app.route('/gallery')
@login_required
def gallery_page():
    return render_template('gallery.html')

@app.route('/admin/analytics/user_contributions', methods=['GET'])
@admin_required # Protect this route
def user_contributions():
    try:
        # Get upload counts per user
        user_upload_counts_cursor = mongo.db['fs.files'].aggregate([
            {"$group": {"_id": "$uploaded_by.uid", "count": {"$sum": 1}}}
        ])

        # Fetch user details for UIDs
        user_contributions_data = {} # Changed variable name to avoid conflict
        user_ids = [item['_id'] for item in user_upload_counts_cursor if item['_id']] # Filter out potential None UIDs

        user_info = {}
        if user_ids:
             try:
                 # Fetch user records in batches if there are many users
                 # Max allowed UIDs in auth.get_users is 100
                 batch_size = 99
                 for i in range(0, len(user_ids), batch_size):
                     batch_uids = user_ids[i:i+batch_size]
                     # Ensure batch_uids is not empty before calling auth.get_users
                     if batch_uids:
                         for user_record in auth.get_users(batch_uids).users:
                             user_info[user_record.uid] = user_record.display_name if user_record.display_name else user_record.email
             except Exception as e:
                 print(f"Error fetching user info for user contributions chart labels: {e}") # Added more specific log
                 # Proceed without user names if fetching fails

        # Reset cursor to iterate again for processing results
        user_upload_counts_cursor = mongo.db['fs.files'].aggregate([
            {"$group": {"_id": "$uploaded_by.uid", "count": {"$sum": 1}}}
        ])


        for item in user_upload_counts_cursor:
            user_id = item['_id']
            count = item['count']
            if user_id:
                label = user_info.get(user_id, user_id) # Use name/email or UID
                user_contributions_data[label] = count # Store in the new variable
            else:
                 # Handle files uploaded without a recorded UID if necessary
                 user_contributions_data['Unknown User'] = user_contributions_data.get('Unknown User', 0) + count


        return jsonify(user_contributions_data), 200 # Return the new variable

    except Exception as e:
        print(f"Generic error generating user contributions data: {e}") # Added more specific log
        return jsonify({"error": f"Failed to load user contributions data: {str(e)}"}), 500

@app.route('/files/list', methods=['GET'])
@login_required
def list_files():
    try:
        files_cursor = mongo.db['fs.files'].find().sort("upload_date", -1)

        file_list = []
        for file in files_cursor:
            file_list.append({
                "file_id": str(file["_id"]),
                "filename": file.get("filename", "N/A"),
                "title": file.get("title", ""),
                "description": file.get("description", ""),
                "language": file.get("language", ""),
                "state": file.get("state", ""),
                "category": file.get("category", ""),
                "tags": ", ".join(file.get("tags", []))
            })

        return jsonify(file_list), 200

    except Exception as e:
        print(f"Error fetching files: {e}")
        return jsonify({"error": f"Failed to fetch files: {str(e)}"}), 500

if __name__ == "__main__":
    # Ensure firebase_admin is initialized before running the app
    if not firebase_admin._apps:
         try:
             cred = credentials.Certificate("serviceAccountKey.json")
             firebase_admin.initialize_app(cred)
             print("Firebase Admin SDK initialized successfully in __main__.")
         except Exception as e:
             print(f"Error initializing Firebase Admin SDK in __main__: {e}")

    app.run(debug=True)
