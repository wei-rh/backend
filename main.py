import uvicorn
from fastapi import FastAPI

from routers import user

app = FastAPI()

app.include_router(user.router)


@app.get("/")
async def root():
    return {"message": "Hello Bigger Applications!"}

if __name__ == '__main__':

    uvicorn.run(app, host="0.0.0.0", port=8000)