# main.py
import sys
from helpers.logger import setup_logger
from helpers.file_handler import load_config
from helpers.arguments_parser import parse_arguments
from helpers.file_handler import load_file, save_file, process_file

def main():
    """
    Main function to run the company information censor
    """
    # Set up logger
    logger = setup_logger()
    
    try:
        # Load configuration
        logger.info("Loading configuration")
        config = load_config(logger)
        logger.info(f"Configuration loaded: {len(config.get('keywords', []))} keywords found")
        
        # Parse command line arguments
        args = parse_arguments(logger)
        
        # Call the censor_switch function with appropriate arguments
        result = process_file(args.input, args.output, config, logger)
        
        if result:
            logger.info("Processing completed successfully")
        else:
            logger.error("Processing failed")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()