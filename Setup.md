# Weather App Setup Guide

## Prerequisites
- Python 3.8 or higher
- pip package manager

## Installation Steps

1. Clone the repository
```bash
git clone https://github.com/kuldeepsharma1/Weather_App
cd Weather_App
```

2. Create a virtual environment
```bash
python -m venv venv
```

3. Activate the virtual environment
```bash
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

4. Install required packages
```bash
pip install -r requirements.txt 

```

5. Create a `.env` file
```bash
# For Windows
copy .env.local .env
# For macOS/Linux
cp .env.local .env
```
Add your environment variables (like API keys) to this file.

6. Run the application
```bash
python app.py
```

## Project Structure
```
Weather_App/
├── static/
│   └── css/
├── templates/
├── .env
├── app.py
└── requirements.txt
```

## Additional Notes
- Make sure to keep your API keys secure
- Update `requirements.txt` using `pip freeze > requirements.txt`
- Access the application at `http://localhost:5000`


# Create Secret Key

1. Generate a secure secret key
```python
# In Python console
import secrets
secrets.token_hex(16)
```

2. Add the secret key to your `.env` file
```bash
# Add this line to .env
SECRET_KEY=your_generated_key_here
```

