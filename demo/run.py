"""Start the demo web server."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("demo.main:app", host="127.0.0.1", port=8000, reload=False)