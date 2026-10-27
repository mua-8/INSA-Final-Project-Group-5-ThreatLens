import {
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
  writeBatch
} from "firebase/firestore";
import { db, firebaseConfig } from "./firebase.js";

const FIRESTORE_ENABLED_URL = `https://console.firebase.google.com/project/${firebaseConfig.projectId}/firestore`;

/**
 * Diagnostic check for Firebase Firestore status
 */
export async function checkFirebaseConnection() {
  try {
    const testCol = collection(db, "system_health");
    const testDoc = doc(testCol, "ping");
    await setDoc(testDoc, {
      service: "ThreatLens SOC Firebase Backend",
      timestamp: serverTimestamp(),
      projectId: firebaseConfig.projectId,
      status: "online"
    });
    return {
      connected: true,
      projectId: firebaseConfig.projectId,
      authDomain: firebaseConfig.authDomain,
      storageBucket: firebaseConfig.storageBucket,
      message: "Firebase Firestore is active and receiving writes."
    };
  } catch (err) {
    const isNotEnabled = (err.message && err.message.includes("Cloud Firestore API has not been used")) ||
                         err.code === "permission-denied";
    return {
      connected: false,
      projectId: firebaseConfig.projectId,
      authDomain: firebaseConfig.authDomain,
      storageBucket: firebaseConfig.storageBucket,
      error: err.message,
      errorCode: err.code,
      isNotEnabled,
      enableUrl: FIRESTORE_ENABLED_URL,
      message: isNotEnabled
        ? `Firestore database needs to be enabled in Firebase Console for project '${firebaseConfig.projectId}'.`
        : err.message
    };
  }
}

/**
 * Fetch all events from Firestore
 */
export async function getFirebaseEvents(params = {}) {
  const eventsCol = collection(db, "events");
  let q = query(eventsCol, limit(params.limit || 50));
  const snapshot = await getDocs(q);
  const events = [];
  snapshot.forEach(docSnap => {
    events.push({ id: docSnap.id, ...docSnap.data() });
  });
  return {
    events,
    count: events.length,
    backend: "firebase"
  };
}

/**
 * Fetch all alerts from Firestore
 */
export async function getFirebaseAlerts(params = {}) {
  const alertsCol = collection(db, "alerts");
  let q = query(alertsCol, limit(params.limit || 50));
  const snapshot = await getDocs(q);
  const alerts = [];
  snapshot.forEach(docSnap => {
    alerts.push({ id: docSnap.id, ...docSnap.data() });
  });
  return {
    alerts,
    count: alerts.length,
    backend: "firebase"
  };
}

/**
 * Update alert triage status in Firestore
 */
export async function updateFirebaseAlertStatus(id, status) {
  const alertRef = doc(db, "alerts", String(id));
  await updateDoc(alertRef, {
    status,
    updated_at: new Date().toISOString()
  });
  return { ok: true, id, status, backend: "firebase" };
}

/**
 * Fetch SOC Dashboard Statistics from Firestore
 */
export async function getFirebaseStatistics() {
  const statsDocRef = doc(db, "statistics", "current");
  const statsSnap = await getDoc(statsDocRef);

  if (statsSnap.exists()) {
    return { ...statsSnap.data(), backend: "firebase" };
  }

  // Count from collections if aggregate doc doesn't exist yet
  const eventsSnap = await getDocs(collection(db, "events"));
  const alertsSnap = await getDocs(collection(db, "alerts"));

  let critical = 0, high = 0, medium = 0, low = 0;
  alertsSnap.forEach(d => {
    const sev = (d.data().severity || "").toLowerCase();
    if (sev === "critical") critical++;
    else if (sev === "high") high++;
    else if (sev === "medium") medium++;
    else low++;
  });

  return {
    total_events: eventsSnap.size,
    total_alerts: alertsSnap.size,
    accepted: 0,
    alerts_by_severity: { critical, high, medium, low },
    backend: "firebase"
  };
}

/**
 * Batch sync local database items into Firebase Firestore
 */
export async function syncLocalToFirebase(localEvents, localAlerts, localStats) {
  const batch = writeBatch(db);

  // Sync statistics
  if (localStats) {
    const statsDocRef = doc(db, "statistics", "current");
    batch.set(statsDocRef, {
      ...localStats,
      synced_at: new Date().toISOString()
    });
  }

  // Sync events
  if (Array.isArray(localEvents)) {
    localEvents.slice(0, 50).forEach(ev => {
      const docRef = doc(db, "events", String(ev.id || ev.line_hash || Math.random().toString(36).substr(2, 9)));
      batch.set(docRef, { ...ev, synced_at: new Date().toISOString() }, { merge: true });
    });
  }

  // Sync alerts
  if (Array.isArray(localAlerts)) {
    localAlerts.slice(0, 50).forEach(al => {
      const docRef = doc(db, "alerts", String(al.id || Math.random().toString(36).substr(2, 9)));
      batch.set(docRef, { ...al, synced_at: new Date().toISOString() }, { merge: true });
    });
  }

  await batch.commit();
  return { ok: true, synced: true, message: "Successfully synced records to Firebase Firestore!" };
}
