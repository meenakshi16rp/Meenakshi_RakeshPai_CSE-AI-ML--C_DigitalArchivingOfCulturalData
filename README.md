# Meenakshi_RakeshPai_CSE-AI-ML-C_DigitalArchivingOfCulturalData

Archive Mosaic - Cultural Heritage Digital Platform
Overview
Archive Mosaic is a secure, scalable, and user-friendly digital platform built to archive and preserve diverse forms of cultural heritage. It enables users and organizations to upload, categorize, and store traditional dances, music, art, manuscripts, and other culturally significant materials. Our platform ensures that these valuable assets remain accessible, organized, and protected for future generations.

Features Implemented ✅
1. User Authentication
Firebase Authentication is used for secure sign-in and sign-up.

Role-based Access Control:

Users are assigned roles (user or admin) upon registration.

Role-based dynamic routing ensures users are directed to the appropriate dashboard.

Session Management:

Secure sessions managed using JWT (JSON Web Tokens) for encrypted authentication.

2. User Management
User Dashboard:

Submit new cultural artifact records (images, videos, PDFs).

Edit or delete only their own submissions.

Admin Dashboard:

View all users and their uploads.

Edit or delete any user account.

Manage user roles (upgrade user to admin, restrict access).

3. Uploading and Metadata
Upload Page:

Supports images, videos, and PDFs.

Allows manual metadata entry (e.g., title, description, author, category).

MongoDB:

All uploads and metadata are securely stored in a MongoDB database.

4. Media Gallery
Gallery Page:

Displays uploaded artifacts.

Responsive and user-friendly design.

Filtering and Search:

Users can search and filter uploads based on metadata fields.

5. AI Integration
Image Captioning Model:

Integrated meta-llama/Llama-Vision-Free model via Together API.

Automatically generates structured image captions (Title + Description) during upload.

Captions are stored alongside manual metadata to enrich the archive.

6. Password Recovery
Forgot Password Feature:

Secure password reset link sent via email.

Allows users to create a new password safely.

7. Frontend Pages
Sign In / Sign Up Pages (with role assignment).

About Us Section (responsive design).

Smooth Navigation between all pages.

Technologies Used 🛠️

Category	Technology/Service
Frontend	HTML, CSS, Bootstrap
Backend	Python (Flask)
Authentication	Firebase Authentication
Database	MongoDB (Atlas)
AI Integration	meta-llama/Llama-Vision-Free (Together API)
Session Control	JWT (JSON Web Tokens)
Hosting (optional)	Can be deployed on Render/Heroku etc.
Project Structure 📁
lua
Copy
Edit
/archive-mosaic
|-- /templates
|    |-- login.html
|    |-- signup.html
|    |-- dashboard_user.html
|    |-- dashboard_admin.html
|    |-- upload.html
|    |-- gallery.html
|    |-- forgot_password.html
|-- /static
|    |-- css/
|    |-- js/
|    |-- images/
|-- app.py
|-- requirements.txt
|-- README.md
Setup Instructions ⚙️
Clone the Repository

bash
Copy
Edit
git clone https://github.com/your-username/archive-mosaic.git
cd archive-mosaic
Install Dependencies

bash
Copy
Edit
pip install -r requirements.txt
Set up Firebase

Create a Firebase project.

Enable Email/Password Authentication.

Download the firebase-adminsdk JSON and set up the necessary environment variables.

Set up MongoDB

Create a MongoDB Atlas cluster.

Update MongoDB URI in your app.py.

Environment Variables

ini
Copy
Edit
FLASK_SECRET_KEY=your_secret_key
FIREBASE_API_KEY=your_firebase_api_key
FIREBASE_PROJECT_ID=your_project_id
MONGODB_URI=your_mongodb_uri
Run the Application

bash
Copy
Edit
python app.py
Access

Visit http://localhost:5000 to access the application.

Pending Work (Optional Future Enhancements) 🛠️
(All current planned tasks are completed. These are just ideas for future expansion.)

Improve UI/UX with Material UI or Tailwind.

Multi-language support (for global cultural data).

Public Gallery (view-only access without login).

Advanced AI features (tag suggestions, OCR for manuscripts).

Analytics dashboard for Admin (number of uploads, user growth, etc.)

Credits 🙏
Developed by: Meenakshi

Special thanks to the Firebase, MongoDB, and Together API communities for their excellent services.

License 📜
This project is licensed under the MIT License.
