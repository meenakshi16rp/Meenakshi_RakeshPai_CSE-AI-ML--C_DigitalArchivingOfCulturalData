  // Import the functions you need from the SDKs you need
  import { initializeApp } from "https://www.gstatic.com/firebasejs/11.4.0/firebase-app.js";
  import { getAnalytics } from "https://www.gstatic.com/firebasejs/11.4.0/firebase-analytics.js";
  import { getAuth, createUserWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/11.4.0/firebase-auth.js";
//your firebase configuration
const firebaseConfig = {
  
  };

  // Initialize Firebase
  const app = initializeApp(firebaseConfig);
  const analytics = getAnalytics(app);

  //initailize authentication
  const auth = getAuth(app);
  
  //submit button for sign up
  const submitsignup= document.getElementById('submitsignup');

  // Add event listener to the button
  submitsignup.addEventListener("click", function(event){
      event.preventDefault()

      //get input values
      const fullname= document.getElementById('fullname').value;
      const email= document.getElementById('email').value;
      const password= document.getElementById('password').value;

      //sign up new users
     createUserWithEmailAndPassword(auth, email, password)
      .then((userCredential) => {
      // Signed up 
      const user = userCredential.user;
      alert("creating account...")
      console.log("User signed up:", user);
      window.location.href="/signin"
      // ...
      })
     .catch((error) => {
       const errorCode = error.code;
       const errorMessage = error.message;
       alert(errorMessage)
       // ..
       console.log("Error during signup:", errorCode, errorMessage);
      });
    })
