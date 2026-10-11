"""
NexGuard AI — Stripe billing (TEST mode).

Thin wrapper around the Stripe SDK for Premium subscriptions. Everything is
import-/config-guarded so the app runs fine when Stripe keys are absent
(billing endpoints then report `enabled: False`). Use TEST keys + test cards.

Required env (backend/.env):
    STRIPE_SECRET_KEY        (sk_test_...)
    STRIPE_PUBLISHABLE_KEY   (pk_test_...)
    STRIPE_WEBHOOK_SECRET    (whsec_...)
Optional:
    STRIPE_PRICE_ID          (price_...) — reuse an existing recurring price;
                             if unset, a $9.99/mo TEST product+price is created
                             lazily on first checkout.
"""
import os

try:
    import stripe
except Exception:                       # pragma: no cover
    stripe = None

SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "").strip()
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
PRICE_ID_ENV = os.getenv("STRIPE_PRICE_ID", "").strip()

PREMIUM_AMOUNT_CENTS = 999             # $9.99 / month (TEST)
PREMIUM_CURRENCY = "usd"

_cached_price_id = PRICE_ID_ENV or None

if stripe and SECRET_KEY:
    stripe.api_key = SECRET_KEY


def is_enabled() -> bool:
    """True only when the SDK is present and a secret key is configured."""
    return bool(stripe and SECRET_KEY)


def config() -> dict:
    return {
        "enabled": is_enabled(),
        "publishable_key": PUBLISHABLE_KEY if is_enabled() else "",
        "webhook_configured": bool(WEBHOOK_SECRET),
    }


def _get_or_create_price() -> str:
    """Return a recurring Price id, creating a TEST one on first use if needed."""
    global _cached_price_id
    if _cached_price_id:
        return _cached_price_id
    product = stripe.Product.create(name="NexGuard AI Premium")
    price = stripe.Price.create(
        product=product.id,
        unit_amount=PREMIUM_AMOUNT_CENTS,
        currency=PREMIUM_CURRENCY,
        recurring={"interval": "month"},
    )
    _cached_price_id = price.id
    return _cached_price_id


def create_checkout_session(user, success_url: str, cancel_url: str):
    """
    Create a subscription Checkout session for the Premium plan.
    Returns the Stripe-hosted Checkout URL.
    """
    kwargs = {
        "mode": "subscription",
        "line_items": [{"price": _get_or_create_price(), "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(user.id),
        # Link the Stripe customer back to our user via metadata.
        "subscription_data": {"metadata": {"user_id": str(user.id)}},
        "allow_promotion_codes": True,
    }
    if getattr(user, "stripe_customer_id", None):
        kwargs["customer"] = user.stripe_customer_id
    else:
        kwargs["customer_email"] = user.email
    session = stripe.checkout.Session.create(**kwargs)
    return session.url


def construct_event(payload: bytes, sig_header: str):
    """Verify + parse a webhook event. Raises on bad signature."""
    return stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)


# Subscription statuses that count as an active paying Premium member.
ACTIVE_STATUSES = {"active", "trialing", "past_due"}
