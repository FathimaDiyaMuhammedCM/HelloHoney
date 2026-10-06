const mongoose = require('mongoose');

async function connectDB(uri) {
  const mongoUri = uri || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/hellohoney';
  try {
    await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 4000 });
    console.log('[DB] Connected to MongoDB:', mongoUri);
    return { mode: 'mongodb' };
  } catch (err) {
    console.warn('[DB] Local MongoDB unavailable:', err.message);
    console.log('[DB] Starting in-memory MongoDB (lab/demo mode)...');
    const { MongoMemoryServer } = require('mongodb-memory-server');
    const mem = await MongoMemoryServer.create();
    await mongoose.connect(mem.getUri());
    console.log('[DB] Connected to in-memory MongoDB');
    return { mode: 'memory', server: mem };
  }
}

module.exports = connectDB;
