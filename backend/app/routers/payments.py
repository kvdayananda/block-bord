"""
Block Bord AI — Payments Router
Routes: /pricing, /checkout/{plan}, /payment/verify, /webhooks/razorpay
"""
import hmac
import hashlib
import logging
import os
from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user, validate_csrf
from backend.app.services.plan_service import PLAN_PRICES_PAISE, set_user_plan
from database import User, Payment

# Optional dependency check
try:
    import razorpay
except ImportError:
    razorpay = None

logger = logging.getLogger("blockbord.payments")
router = APIRouter(tags=["Payments"])
templates = Jinja2Templates(directory="frontend/templates")


# ──────────────────────────────────────────────────────────────
# PRICING
# ──────────────────────────────────────────────────────────────
@router.get("/pricing", response_class=HTMLResponse)
def pricing_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("pricing.html", {"request": request, "user": user})


# ──────────────────────────────────────────────────────────────
# CHECKOUT
# ──────────────────────────────────────────────────────────────
@router.get("/checkout/{plan_name}")
def checkout(plan_name: str, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login?message=Please log in to upgrade", status_code=302)
    
    plan_name = plan_name.lower()
    amount = PLAN_PRICES_PAISE.get(plan_name)
    if not amount:
        return RedirectResponse("/pricing", status_code=302)

    # Simulation Mode (if no Razorpay keys)
    razorpay_id = os.getenv("RAZORPAY_KEY_ID")
    razorpay_secret = os.getenv("RAZORPAY_KEY_SECRET")
    
    if not razorpay or not razorpay_id or not razorpay_secret:
        logger.info(f"Payment simulation for {user.username}: {plan_name}")
        set_user_plan(user, plan_name)
        db.commit()
        return RedirectResponse("/app?message=Plan upgraded successfully (Test Mode)", status_code=302)

    client = razorpay.Client(auth=(razorpay_id, razorpay_secret))
    order_data = {
        "amount": amount,
        "currency": "INR",
        "receipt": f"receipt_{user.id}_{int(os.getpid())}",
        "payment_capture": 1
    }
    
    try:
        order = client.order.create(data=order_data)
        db.add(Payment(
            user_id=user.id,
            plan=plan_name,
            amount=amount,
            razorpay_order_id=order["id"],
            status="created"
        ))
        db.commit()
        
        return templates.TemplateResponse("checkout.html", {
            "request": request,
            "user": user,
            "order": order,
            "razorpay_key": razorpay_id,
            "plan_name": plan_name.capitalize()
        })
    except Exception as e:
        logger.error(f"Razorpay order Error: {e}")
        return RedirectResponse("/pricing?error=Payment gateway error", status_code=302)


# ──────────────────────────────────────────────────────────────
# VERIFY PAYMENT
# ──────────────────────────────────────────────────────────────
@router.post("/payment/verify")
def verify_payment(
    request: Request,
    razorpay_order_id: str = Form(...),
    razorpay_payment_id: str = Form(...),
    razorpay_signature: str = Form(...),
    db: Session = Depends(get_db)
):
    payment = db.query(Payment).filter(Payment.razorpay_order_id == razorpay_order_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment record not found")

    razorpay_secret = os.getenv("RAZORPAY_KEY_SECRET", "")
    
    # Signature verification
    params_dict = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }
    
    try:
        # client.utility.verify_payment_signature(params_dict) — manually or via client
        data = f"{razorpay_order_id}|{razorpay_payment_id}"
        generated_signature = hmac.new(
            razorpay_secret.encode(), data.encode(), hashlib.sha256
        ).hexdigest()
        
        if generated_signature != razorpay_signature:
            payment.status = "failed"
            db.commit()
            return RedirectResponse("/pricing?error=Signature mismatch", status_code=302)

        payment.status = "paid"
        payment.razorpay_payment_id = razorpay_payment_id
        payment.razorpay_signature = razorpay_signature
        
        user = db.query(User).filter(User.id == payment.user_id).first()
        set_user_plan(user, payment.plan)
        db.commit()
        
        logger.info(f"Payment SUCCESS for {user.username} - Plan: {payment.plan}")
        return RedirectResponse("/app?message=Subscription active!", status_code=302)
        
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return RedirectResponse("/pricing?error=Verification failed", status_code=302)


# ──────────────────────────────────────────────────────────────
# WEBHOOK
# ──────────────────────────────────────────────────────────────
@router.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature")
    secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")

    if not signature or not secret:
        return JSONResponse({"status": "ignored"}, status_code=200)

    # Verification using HMAC object (fixed from monolith hmac.new crash)
    h = hmac.new(secret.encode(), body, hashlib.sha256)
    expected = h.hexdigest()

    if expected != signature:
        logger.error("Razorpay webhook signature mismatch")
        raise HTTPException(status_code=400, detail="Invalid signature")

    data = await request.json()
    event = data.get("event")
    
    if event == "payment.captured":
        payload = data.get("payload", {}).get("payment", {}).get("entity", {})
        order_id = payload.get("order_id")
        
        payment = db.query(Payment).filter(Payment.razorpay_order_id == order_id).first()
        if payment and payment.status != "paid":
            payment.status = "paid"
            payment.razorpay_payment_id = payload.get("id")
            
            user = db.query(User).filter(User.id == payment.user_id).first()
            if user:
                set_user_plan(user, payment.plan)
            db.commit()
            logger.info(f"Webhook: Payment captured for order {order_id}")

    return {"status": "ok"}
