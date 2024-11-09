from src.lib.api.mega import Mega

email: str = "fut4dbd@gmail.com"
password: str = "deathAchilles!@##@!1"

m = Mega()
m = m.login(email, password)
