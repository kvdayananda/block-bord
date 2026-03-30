import os
from pathlib import Path

def main():
    print("--- Block Bord AI Dataset Initialization ---")
    
    # 1. Ensure models directory exists
    model_dir = Path("models")
    if not model_dir.exists():
        print(f"Creating directory: {model_dir}")
        model_dir.mkdir(parents=True, exist_ok=True)
    else:
        print(f"Directory exists: {model_dir}")
        
    # 2. Check for required models
    required_models = ["spam_model.bin", "sklearn_model.joblib"]
    missing_models = []
    
    for model in required_models:
        model_path = model_dir / model
        if model_path.exists():
            size_mb = model_path.stat().st_size / (1024 * 1024)
            print(f"✅ Found {model} ({size_mb:.2f} MB)")
        else:
            missing_models.append(model)
            print(f"❌ Missing {model}")
            
    if missing_models:
        print("\n[WARNING] Some models are missing. The AI risk engine will run in heuristic-only mode.")
        print("In a production environment, ensure these files are present in the 'models/' directory.")
    else:
        print("\n✅ All core AI models are initialized and ready.")

    print("\nInitialization complete. You can now start the server with:")
    print("python -m uvicorn app:app --reload")

if __name__ == "__main__":
    main()
