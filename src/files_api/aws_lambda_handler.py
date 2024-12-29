from mangum import Mangum
from files_api.main import create_app

APP = create_app()
handler = Mangum(APP)

