import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";


const firebaseConfig = {
  apiKey: "AIzaSyDYMtSJE8zDJxeu5RXHbtXT1loyNfLcKyk",
  authDomain: "agent-browser-366c1.firebaseapp.com",
  projectId: "agent-browser-366c1",
  storageBucket: "agent-browser-366c1.firebasestorage.app",
  messagingSenderId: "637934017963",
  appId: "1:637934017963:web:e90b08d4b72a3861de86ee",
  measurementId: "G-ZH2H0WXJJX"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });

export { auth, db, googleProvider };
