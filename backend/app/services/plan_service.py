"""
Block Bord AI — Plan / Subscription Service
Centralizes all plan-related logic: limits, pricing, get/set plan.
"""
from database import User

# ── Scan limits per plan (None = unlimited) ──
PLAN_LIMITS: dict = {
    "free": 10,
    "starter": 50,
    "pro": None,
    "business": None,
}

# ── Prices in Indian Paise (1 INR = 100 paise) ──
PLAN_PRICES_PAISE: dict = {
    "starter": 9900,    # ₹99
    "pro": 19900,       # ₹199
    "business": 49900,  # ₹499
}

PLAN_NAMES = list(PLAN_LIMITS.keys())


def get_user_plan(user: User) -> str:
    """Returns the user's current plan name (always one of PLAN_LIMITS keys)."""
    plan = (getattr(user, "plan", None) or "").strip().lower()
    if plan in PLAN_LIMITS:
        return plan
    return "pro" if getattr(user, "is_pro", False) else "free"


def set_user_plan(user: User, plan: str) -> None:
    """Updates user.plan and user.is_pro atomically. Commit after calling this."""
    plan = (plan or "").strip().lower()
    if plan not in PLAN_LIMITS:
        plan = "free"
    user.plan = plan
    user.is_pro = plan in ("pro", "business")


def get_plan_limit(plan: str) -> int | None:
    """Returns the daily scan limit for a plan, or None for unlimited."""
    return PLAN_LIMITS.get(plan)


def get_plan_price(plan: str) -> int | None:
    """Returns the plan price in paise, or None if the plan is free."""
    return PLAN_PRICES_PAISE.get(plan)
