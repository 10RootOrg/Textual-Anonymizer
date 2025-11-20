# helpers/arguments_parser.py
import argparse
import os

def parse_arguments(logger=None):
    """
    Parse command line arguments
    
    Args:
        logger (logging.Logger, optional): Logger instance
        
    Returns:
        argparse.Namespace: Parsed arguments
    """
    if logger:
        logger.debug("Parsing command line arguments")
    
    parser = argparse.ArgumentParser(description='Censor company information in text')
    parser.add_argument('--input', help='Input file path (if not provided, will read from stdin)')
    parser.add_argument('--output', help='Output file path (if not provided, will write to stdout)')
    
    args = parser.parse_args()
    
    # Log argument details if logger is provided
    if logger:
        if args.input:
            logger.info(f"Input file: {args.input}")
            if not os.path.exists(args.input):
                logger.warning(f"Input file does not exist: {args.input}")
        else:
            logger.info("Reading from stdin")
            
        if args.output:
            logger.info(f"Output file: {args.output}")
        else:
            logger.info("Writing to stdout")
    
    return args