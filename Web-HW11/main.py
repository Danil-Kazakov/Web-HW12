import uvicorn
from fastapi import FastAPI

import routes

app = FastAPI()

app.include_router(routes.app, prefix='/contacts')
app.include_router(routes.router, prefix='/auth')


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
