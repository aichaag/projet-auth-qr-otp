from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    User.query.filter_by(email="test@exemple.com").delete()
    
    user = User(
        email="test@exemple.com",
        phone_number="+33612345678"  # Format international
    )
    user.set_password("password123")
    
    db.session.add(user)
    db.session.commit()
    print(f"✅ Utilisateur créé avec succès !")
    print(f"   Email : {user.email}")
    print(f"   Téléphone : {user.phone_number}")
    print(f"   Mot de passe : password123")