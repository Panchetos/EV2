# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="FERREMAS Integration API",
    description="API de integración para la plataforma FERREMAS",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
SECRET_KEY = "ferremas_secret_key_2025"
ALGORITHM = "HS256"

# External API Configuration
FERREMAS_API_URL = "https://ea2p2assets-production.up.railway.app"
FERREMAS_TOKEN = "SaGrP9ojGS39hU9ljqbXxQ=="
FERREMAS_HEADERS = {"Authorization": f"Bearer {FERREMAS_TOKEN}"}

# Database simulation
users_db = {
    "javier_thompson": {
        "username": "javier_thompson", 
        "password": "aONF4d6aNBIxRjlgjBRRzrS", 
        "role": "admin",
        "permissions": ["read", "write", "delete", "admin"]
    },
    "ignacio_tapia": {
        "username": "ignacio_tapia", 
        "password": "f7rWChmQS1JYfThT", 
        "role": "client",
        "permissions": ["read"]
    },
    "stripe_sa": {
        "username": "stripe_sa", 
        "password": "dzkQqDL9XZH33YDzhmsf", 
        "role": "service_account",
        "permissions": ["read", "write"]
    }
}

# Pydantic Models
class User(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user_role: str

class ProductCreate(BaseModel):
    name: str
    price: float
    category: str
    stock: int
    description: Optional[str] = None

class Order(BaseModel):
    product_id: int
    quantity: int
    customer_info: dict

class MultiProductOrder(BaseModel):
    items: List[dict]
    customer_info: dict

class ContactRequest(BaseModel):
    name: str
    email: str
    message: str
    vendor_id: Optional[int] = None

class PaymentRequest(BaseModel):
    amount: float
    currency: str = "CLP"
    payment_method: str
    order_id: str

class CurrencyConversion(BaseModel):
    from_currency: str
    to_currency: str
    amount: float

# Utility Functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

def check_permission(required_permission: str):
    def permission_checker(token_data: dict = Depends(verify_token)):
        username = token_data.get("sub")
        user = users_db.get(username)
        if not user or required_permission not in user["permissions"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user
    return permission_checker

# Routes
@app.get("/", tags=["Root"])
def root():
    return {
        "message": "FERREMAS Integration API v2.0",
        "status": "active",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Authentication Routes
@app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
def login(user: User):
    """Authenticate user and return JWT token"""
    db_user = users_db.get(user.username)
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    access_token = create_access_token(
        data={"sub": user.username, "role": db_user["role"]}
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=86400,  # 24 hours
        user_role=db_user["role"]
    )

@app.get("/auth/me", tags=["Authentication"])
def get_current_user(token_data: dict = Depends(verify_token)):
    """Get current user information"""
    username = token_data.get("sub")
    user = users_db.get(username)
    return {
        "username": user["username"],
        "role": user["role"],
        "permissions": user["permissions"]
    }

# Products Routes
@app.get("/products", tags=["Products"])
def get_products(user: dict = Depends(check_permission("read"))):
    """Get all products (mock)"""
    return [
        {"id": 1, "name": "Martillo", "price": 4990, "stock": 12, "category": "Herramientas"},
        {"id": 2, "name": "Taladro", "price": 29990, "stock": 5, "category": "Herramientas Eléctricas"},
        {"id": 3, "name": "Cemento", "price": 6500, "stock": 20, "category": "Materiales Básicos"}
    ]

@app.get("/products/promotions", tags=["Products"])
def get_promotions(user: dict = Depends(check_permission("read"))):
    return [
        {"id": 1, "name": "Martillo", "price": 3990, "promo": True}
    ]

@app.get("/products/novelties", tags=["Products"])
def get_novelties(user: dict = Depends(check_permission("read"))):
    return [
        {"id": 2, "name": "Taladro", "price": 29990, "novelty": True}
    ]

@app.get("/products/{product_id}", tags=["Products"])
def get_product(product_id: int, user: dict = Depends(check_permission("read"))):
    """Mock single product"""
    products = {
        1: {"id": 1, "name": "Martillo", "price": 4990},
        2: {"id": 2, "name": "Taladro", "price": 29990}
    }
    product = products.get(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


@app.post("/products", tags=["Products"])
def create_product(product: ProductCreate, user: dict = Depends(check_permission("write"))):
    """Create new product (admin/maintainer only)"""
    # Mock implementation - in real scenario, this would call the backend API
    return {
        "message": "Product created successfully",
        "product": product.dict(),
        "created_by": user["username"]
    }

# Branches Routes
@app.get("/branches", tags=["Branches"])
def get_branches(user: dict = Depends(check_permission("read"))):
    """Get all branches"""
    try:
        response = requests.get(f"{FERREMAS_API_URL}/branches", headers=FERREMAS_HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching branches: {e}")
        raise HTTPException(status_code=500, detail="Error fetching branches")

@app.get("/branches/{branch_id}", tags=["Branches"])
def get_branch(branch_id: int, user: dict = Depends(check_permission("read"))):
    """Get specific branch details"""
    try:
        response = requests.get(f"{FERREMAS_API_URL}/branches/{branch_id}", headers=FERREMAS_HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching branch {branch_id}: {e}")
        raise HTTPException(status_code=404, detail="Branch not found")

@app.get("/branches/{branch_id}/vendors", tags=["Branches"])
def get_branch_vendors(branch_id: int, user: dict = Depends(check_permission("read"))):
    """Get vendors for specific branch"""
    try:
        response = requests.get(f"{FERREMAS_API_URL}/branches/{branch_id}/vendors", headers=FERREMAS_HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching vendors for branch {branch_id}: {e}")
        raise HTTPException(status_code=500, detail="Error fetching vendors")

@app.get("/vendors/{vendor_id}", tags=["Vendors"])
def get_vendor(vendor_id: int, user: dict = Depends(check_permission("read"))):
    """Get specific vendor by ID"""
    # Mock implementation
    return {
        "vendor_id": vendor_id,
        "name": f"Vendor {vendor_id}",
        "email": f"vendor{vendor_id}@ferremas.com",
        "phone": "+56912345678"
    }

# Orders Routes
@app.post("/orders", tags=["Orders"])
def place_order(order: Order, user: dict = Depends(check_permission("read"))):
    """Place a single product order"""
    return {
        "message": "Order placed successfully",
        "order_id": f"ORD{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "order": order.dict(),
        "customer": user["username"],
        "status": "pending"
    }

@app.post("/orders/multiProduct", tags=["Orders"])
def place_multi_product_order(order: MultiProductOrder, user: dict = Depends(check_permission("read"))):
    """Place a multi-product order"""
    return {
        "message": "Multi-product order placed successfully",
        "order_id": f"MORD{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "order": order.dict(),
        "customer": user["username"],
        "status": "pending"
    }

# Contact Routes
@app.post("/contact", tags=["Contact"])
def contact_vendor(contact: ContactRequest, user: dict = Depends(check_permission("read"))):
    """Send contact request to vendor"""
    return {
        "message": "Contact request sent successfully",
        "request_id": f"CNT{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "contact": contact.dict(),
        "from_user": user["username"]
    }

# Payment Routes (Stripe Integration)
@app.post("/payments/stripe", tags=["Payments"])
def process_stripe_payment(payment: PaymentRequest, user: dict = Depends(check_permission("read"))):
    """Process payment through Stripe (mock implementation)"""
    # In real implementation, integrate with Stripe API
    return {
        "message": "Payment processed successfully",
        "payment_id": f"PAY{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "amount": payment.amount,
        "currency": payment.currency,
        "status": "completed",
        "stripe_reference": f"pi_mock_{payment.order_id}"
    }

# Currency Conversion Routes
@app.get("/currency/convert", tags=["Currency"])
def convert_currency(from_currency: str, to_currency: str, amount: float):
    """Convert currency using real-time rates"""
    # Mock implementation with realistic rates
    rates = {
        ("CLP", "USD"): 0.0011,
        ("USD", "CLP"): 910.0,
        ("CLP", "EUR"): 0.0010,
        ("EUR", "CLP"): 1000.0
    }
    
    rate_key = (from_currency.upper(), to_currency.upper())
    if rate_key not in rates:
        raise HTTPException(status_code=400, detail="Unsupported currency pair")
    
    converted_amount = amount * rates[rate_key]
    
    return {
        "from_currency": from_currency.upper(),
        "to_currency": to_currency.upper(),
        "original_amount": amount,
        "converted_amount": round(converted_amount, 2),
        "exchange_rate": rates[rate_key],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/currency/convert", tags=["Currency"])
def convert_currency_post(conversion: CurrencyConversion):
    """Convert currency using POST method"""
    return convert_currency(
        conversion.from_currency, 
        conversion.to_currency, 
        conversion.amount
    )

# Admin Routes
@app.get("/admin/users", tags=["Admin"])
def get_users(user: dict = Depends(check_permission("admin"))):
    """Get all users (admin only)"""
    return [
        {
            "username": username,
            "role": user_data["role"],
            "permissions": user_data["permissions"]
        }
        for username, user_data in users_db.items()
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)