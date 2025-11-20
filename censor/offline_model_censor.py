import os
import logging
import subprocess
import sys
import shutil
import spacy
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Use relative path within the project for model storage
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

def ensure_model_exists(model_name, logger):
    """
    Download spaCy model and save it to the specified directory.
    
    Args:
        model_name (str): Name of the spaCy model
        MODEL_DIR (str): Directory to store the model
        logger (logging.Logger): Logger instance
        
    Returns:
        str: Path to the model directory if successful, False otherwise
    """
    logger.info(f"Checking for model {model_name} in {MODEL_DIR}")
    
    # Create model directory if it doesn't exist
    if not os.path.exists(MODEL_DIR):
        logger.info(f"Creating model directory: {MODEL_DIR}")
        os.makedirs(MODEL_DIR, exist_ok=True)
    
    # Define custom model path (project_dir/models/model_name)
    custom_model_path = os.path.join(MODEL_DIR, model_name)
    
    # Check if model already exists in our custom location
    if os.path.exists(custom_model_path) and os.path.isdir(custom_model_path):
        logger.info(f"Model found in custom location: {custom_model_path}")
        try:
            # Try to load from custom location to verify it's valid
            spacy.load(custom_model_path)
            return custom_model_path
        except Exception as e:
            logger.warning(f"Found model directory but couldn't load model: {str(e)}")
            # If loading fails, we'll handle below
            # Remove the invalid model directory
            logger.info(f"Removing invalid model directory: {custom_model_path}")
            shutil.rmtree(custom_model_path, ignore_errors=True)
    
    # Try loading from default location first
    try:
        logger.info(f"Checking if model {model_name} exists in default location...")
        spacy.load(model_name)
        logger.info(f"Model {model_name} found in default location")
        has_model = True
    except OSError:
        has_model = False
        logger.info(f"Model {model_name} not found in default location")
    
    # If model doesn't exist in default location, download it
    if not has_model:
        logger.info(f"Downloading model {model_name}")
        try:
            # Use the standard download approach without flags
            spacy.cli.download(model_name)
            logger.info(f"Model {model_name} downloaded successfully")
        except Exception as e:
            logger.error(f"Error downloading model: {str(e)}")
            
            # Try a fallback approach with subprocess
            try:
                logger.info("Trying alternative download method...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", model_name, "--no-deps"])
                logger.info(f"Alternative download successful for {model_name}")
            except Exception as e2:
                logger.error(f"Both download methods failed: {str(e2)}")
                return False
    
    # Now the model should exist in the default location
    # Load it and save to our custom location
    try:
        logger.info(f"Loading model {model_name} from default location")
        model = spacy.load(model_name)
        
        logger.info(f"Saving model to custom location: {custom_model_path}")
        # Remove any existing directory
        if os.path.exists(custom_model_path):
            shutil.rmtree(custom_model_path, ignore_errors=True)
        
        # Save the model to our custom path
        model.to_disk(custom_model_path)
        
        # Verify we can load from custom path
        logger.info(f"Verifying model at {custom_model_path}")
        spacy.load(custom_model_path)
        
        logger.info(f"Model successfully saved to {custom_model_path}")
        return custom_model_path
    except Exception as e:
        logger.error(f"Error saving model to custom location: {str(e)}")
        return False

def censor_text_presidio(text, keywords, MODEL_NAME, logger=None):
    """
    Censor sensitive information in text using Microsoft Presidio.
    
    Args:
        text (str): Text to censor.
        keywords (list): List of company keywords to help maintain context.
        logger (logging.Logger): Logger instance.
    
    Returns:
        str: Text with sensitive information censored.
    """
    if not text:
        logger.warning("Empty text provided for censoring")
        return ""
    
    logger.info("Beginning text censoring with Presidio")
    original_length = len(text)
    
    # Ensure the model exists, download if necessary
    model_path = ensure_model_exists(MODEL_NAME, logger)
    if not model_path:
        logger.error(f"Could not ensure model {MODEL_NAME} exists")
        return text  # Return original text if model handling fails
    
    # Set up the NLP engine with the spaCy model
    logger.info(f"Using model from: {model_path}")
    nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": model_path}])
    
    # Create registry for recognizers
    # Note: Custom pattern recognizers are handled in a separate file
    registry = RecognizerRegistry()
    
    # Track number of replacements for each type
    stats = {
        "PERSON": 0,
        "EMAIL_ADDRESS": 0,
        "PHONE_NUMBER": 0,
        "CREDIT_CARD": 0,
        "DOMAIN": 0,
        "DATE_TIME": 0,
        "LOCATION": 0,
        "NRP": 0,  # National Registration Product (ID numbers)
        "IP_ADDRESS": 0,
        "US_SSN": 0,
        "US_BANK_NUMBER": 0,
        "IBAN_CODE": 0,
        "US_DRIVER_LICENSE": 0,
        "CRYPTO": 0,
        "URL": 0,
        "COMPANY": 0,
        "MONEY": 0,
        "PASSWORD": 0
    }
    
    # Create analyzer with the nlp engine and registry
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=registry
    )
    
    # Create anonymizer engine
    anonymizer = AnonymizerEngine()
    
    # Define operator configurations for anonymization
    operators = {
        "PERSON": OperatorConfig("replace", {"new_value": "[PERSON_NAME]"}),
        "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
        "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE]"}),
        "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"}),
        "DOMAIN": OperatorConfig("replace", {"new_value": "[DOMAIN]"}),
        "DATE_TIME": OperatorConfig("replace", {"new_value": "[DATE]"}),
        "LOCATION": OperatorConfig("replace", {"new_value": "[ADDRESS]"}),
        "NRP": OperatorConfig("replace", {"new_value": "[ID_NUMBER]"}),
        "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[IP_ADDRESS]"}),
        "US_SSN": OperatorConfig("replace", {"new_value": "[SSN_ID]"}),
        "US_BANK_NUMBER": OperatorConfig("replace", {"new_value": "[BANK_ACCOUNT]"}),
        "IBAN_CODE": OperatorConfig("replace", {"new_value": "[BANK_ACCOUNT]"}),
        "US_DRIVER_LICENSE": OperatorConfig("replace", {"new_value": "[DRIVER_LICENSE]"}),
        "CRYPTO": OperatorConfig("replace", {"new_value": "[CRYPTO_ADDRESS]"}),
        "URL": OperatorConfig("replace", {"new_value": "[URL]"}),
        "COMPANY": OperatorConfig("replace", {"new_value": "[COMPANY_NAME]"}),
        "MONEY": OperatorConfig("replace", {"new_value": "[MONEY]"}),
        "PASSWORD": OperatorConfig("replace", {"new_value": "[PASSWORD]"}),
        "API_KEY": OperatorConfig("replace", {"new_value": "[API_KEY]"})
    }
    
    # Analyze the text
    logger.debug("Analyzing text for PII entities")
    analyzer_results = analyzer.analyze(text=text, language="en")
    
    # Count entities by type
    for result in analyzer_results:
        entity_type = result.entity_type
        if entity_type in stats:
            stats[entity_type] += 1
    
    # Anonymize the text
    logger.debug("Anonymizing identified entities")
    anonymized_text = text
    if analyzer_results:
        anonymizer_result = anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators
        )
        anonymized_text = anonymizer_result.text
    
    # Log statistics
    total_replacements = sum(stats.values())
    logger.info(f"Censoring complete: {total_replacements} replacements made")
    for key, value in stats.items():
        if value > 0:
            logger.info(f"  - {key}: {value} replacements")
    
    new_length = len(anonymized_text)
    logger.debug(f"Text length change: {original_length} -> {new_length} ({new_length - original_length} diff)")
    
    return anonymized_text