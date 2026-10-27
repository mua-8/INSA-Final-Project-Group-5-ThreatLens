// Import the functions you need from the SDKs you need
import { initializeApp, getApps, getApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";
import {
  getFirestore,
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  addDoc,
  updateDoc,
  query,
  where,
  orderBy,
  limit,
  serverTimestamp,
  writeBatch,
  onSnapshot
} from "firebase/firestore";

// Your web app's Firebase configuration
export const firebaseConfig = {
  apiKey: "AIzaSyDlJQF6f-DTaWnsr4LX1FL3mZArwAAj5MY",
  authDomain: "cybergroup6.firebaseapp.com",
  projectId: "cybergroup6",
  storageBucket: "cybergroup6.firebasestorage.app",
  messagingSenderId: "918924440251",
  appId: "1:918924440251:web:b0143daccc9977a362af9e",
  measurementId: "G-QEB44TWQCK"
};

// Initialize Firebase App & Firestore
export const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
export const db = getFirestore(app);

// Initialize Analytics safely (checking browser support)
export const initAnalytics = async () => {
  try {
    if (typeof window !== "undefined" && (await isSupported())) {
      return getAnalytics(app);
    }
  } catch (err) {
    console.warn("Firebase analytics not initialized:", err);
  }
  return null;
};

initAnalytics();
