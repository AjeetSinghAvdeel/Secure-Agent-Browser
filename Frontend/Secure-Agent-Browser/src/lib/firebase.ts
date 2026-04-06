import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";


const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyDYMtSJE8zDJxeu5RXHbtXT1loyNfLcKyk",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "agent-browser-366c1.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "agent-browser-366c1",
  storageBucket:
    import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "agent-browser-366c1.firebasestorage.app",
  messagingSenderId:
    import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "637934017963",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:637934017963:web:e90b08d4b72a3861de86ee",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-ZH2H0WXJJX"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });

export { auth, db, googleProvider };
