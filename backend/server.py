from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta, time
import pytz
import os
import uuid
import pymongo
from pymongo import MongoClient
import jwt
import bcrypt
from bson import ObjectId

# Initialize FastAPI app
app = FastAPI()

# CORS middleware - Updated for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Local development
        "https://*.netlify.app",  # Netlify domains
        "https://*.netlify.com",  # Netlify domains  
        os.environ.get('FRONTEND_URL', '*')  # Production frontend URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URL)
db = client.restaurant_reservations

# Collections
reservations_collection = db.reservations
admin_users_collection = db.admin_users

# JWT settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"

# Security
security = HTTPBearer()

# Philippine timezone
PH_TZ = pytz.timezone('Asia/Manila')

# Business hours and rules
BUSINESS_START = time(10, 0)  # 10:00 AM
BUSINESS_END = time(20, 0)    # 8:00 PM
CLOSED_DAYS = [2, 6]  # Wednesday=2, Sunday=6 (Monday=0)
SLOT_DURATION = 30  # minutes

# Pydantic models
class ReservationCreate(BaseModel):
    customer_name: str
    customer_email: EmailStr
    customer_phone: str
    reservation_date: str  # YYYY-MM-DD
    time_slot: str  # HH:MM
    party_size: int
    special_requests: Optional[str] = ""

class ReservationResponse(BaseModel):
    id: str
    customer_name: str
    customer_email: str
    customer_phone: str
    reservation_date: str
    time_slot: str
    party_size: int
    special_requests: str
    status: str  # pending, approved, denied
    created_at: str

class AdminLogin(BaseModel):
    username: str
    password: str

class ReservationUpdate(BaseModel):
    status: str  # approved, denied

# Initialize default admin user
def create_default_admin():
    existing_admin = admin_users_collection.find_one({"username": "Vienne24"})
    if not existing_admin:
        hashed_password = bcrypt.hashpw("ChillBar2025".encode('utf-8'), bcrypt.gensalt())
        admin_users_collection.insert_one({
            "username": "Vienne24",
            "password": hashed_password
        })

# Helper functions
def generate_time_slots():
    """Generate available time slots for the day"""
    slots = []
    current_time = datetime.combine(datetime.today(), BUSINESS_START)
    end_time = datetime.combine(datetime.today(), BUSINESS_END)
    
    while current_time < end_time:
        slots.append(current_time.strftime("%H:%M"))
        current_time += timedelta(minutes=SLOT_DURATION)
    
    return slots

def is_business_day(date_str):
    """Check if the given date is a business day"""
    date_obj = datetime.strptime(date_str, "%Y-%m-%d")
    return date_obj.weekday() not in CLOSED_DAYS

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return user info"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# API Routes

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(PH_TZ).isoformat()}

@app.get("/api/available-slots/{date}")
async def get_available_slots(date: str):
    """Get available time slots for a specific date"""
    try:
        # Validate date format
        datetime.strptime(date, "%Y-%m-%d")
        
        # Check if it's a business day
        if not is_business_day(date):
            return {"available_slots": [], "message": "ChillBar is closed on this day"}
        
        # Get all time slots
        all_slots = generate_time_slots()
        
        # Get existing reservations for this date (only approved ones count for availability)
        existing_reservations = list(reservations_collection.find({
            "reservation_date": date,
            "status": {"$in": ["approved", "pending"]}  # Consider both pending and approved as unavailable
        }))
        
        # For simplicity, assume each slot can have multiple reservations (restaurant has multiple tables)
        # In a real system, you'd track table capacity
        reserved_slots = [res["time_slot"] for res in existing_reservations]
        
        # For this MVP, let's limit to 5 reservations per slot
        slot_counts = {}
        for slot in reserved_slots:
            slot_counts[slot] = slot_counts.get(slot, 0) + 1
        
        available_slots = [slot for slot in all_slots if slot_counts.get(slot, 0) < 5]
        
        return {"available_slots": available_slots}
    
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

@app.post("/api/reservations")
async def create_reservation(reservation: ReservationCreate):
    """Create a new reservation"""
    try:
        # Validate date is a business day
        if not is_business_day(reservation.reservation_date):
            raise HTTPException(status_code=400, detail="ChillBar is closed on this day")
        
        # Validate time slot
        all_slots = generate_time_slots()
        if reservation.time_slot not in all_slots:
            raise HTTPException(status_code=400, detail="Invalid time slot")
        
        # Check if slot is still available
        existing_count = reservations_collection.count_documents({
            "reservation_date": reservation.reservation_date,
            "time_slot": reservation.time_slot,
            "status": {"$in": ["approved", "pending"]}
        })
        
        if existing_count >= 5:  # Max 5 reservations per slot
            raise HTTPException(status_code=400, detail="Time slot is fully booked")
        
        # Create reservation
        reservation_data = {
            "id": str(uuid.uuid4()),
            "customer_name": reservation.customer_name,
            "customer_email": reservation.customer_email,
            "customer_phone": reservation.customer_phone,
            "reservation_date": reservation.reservation_date,
            "time_slot": reservation.time_slot,
            "party_size": reservation.party_size,
            "special_requests": reservation.special_requests,
            "status": "pending",
            "created_at": datetime.now(PH_TZ).isoformat()
        }
        
        reservations_collection.insert_one(reservation_data)
        
        return {
            "message": "Reservation created successfully",
            "reservation_id": reservation_data["id"],
            "status": "pending"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/login")
async def admin_login(login_data: AdminLogin):
    """Admin login endpoint"""
    admin_user = admin_users_collection.find_one({"username": login_data.username})
    
    if not admin_user or not bcrypt.checkpw(login_data.password.encode('utf-8'), admin_user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    token_data = {"sub": login_data.username}
    token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/admin/reservations")
async def get_all_reservations(current_user: str = Depends(get_current_user)):
    """Get all reservations for admin"""
    reservations = list(reservations_collection.find({}, {"_id": 0}).sort("created_at", -1))
    return {"reservations": reservations}

@app.put("/api/admin/reservations/{reservation_id}")
async def update_reservation_status(
    reservation_id: str, 
    update_data: ReservationUpdate,
    current_user: str = Depends(get_current_user)
):
    """Update reservation status (approve/deny)"""
    if update_data.status not in ["approved", "denied"]:
        raise HTTPException(status_code=400, detail="Status must be 'approved' or 'denied'")
    
    result = reservations_collection.update_one(
        {"id": reservation_id},
        {"$set": {"status": update_data.status}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Reservation not found")
    
    return {"message": f"Reservation {update_data.status} successfully"}

@app.get("/api/admin/dashboard-stats")
async def get_dashboard_stats(current_user: str = Depends(get_current_user)):
    """Get dashboard statistics"""
    total_reservations = reservations_collection.count_documents({})
    pending_reservations = reservations_collection.count_documents({"status": "pending"})
    approved_reservations = reservations_collection.count_documents({"status": "approved"})
    denied_reservations = reservations_collection.count_documents({"status": "denied"})
    
    return {
        "total_reservations": total_reservations,
        "pending_reservations": pending_reservations,
        "approved_reservations": approved_reservations,
        "denied_reservations": denied_reservations
    }

# Initialize default admin on startup
@app.on_event("startup")
async def startup_event():
    create_default_admin()
    print("ChillBar by VIENNE - Default admin created: username=Vienne24, password=ChillBar2025")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)