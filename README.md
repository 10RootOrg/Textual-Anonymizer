# Anonimizer

A powerful document anonymization tool for redacting PII (Personally Identifiable Information) and sensitive company data from multiple document formats.

## Features

- **Multi-Format Support**: Process PDF, DOCX, TXT, MD, JSON, CSV, Excel (XLSX), XML, and HTML files
- **Dual Censoring Engine**:
  - **Regex-based**: Fast pattern matching for structured PII
  - **NLP-based**: Machine learning approach using Presidio and spaCy for enhanced recognition
- **Comprehensive PII Detection**:
  - Company names and keywords
  - Email addresses and domain names
  - API keys and tokens (AWS, Google, Stripe, GitHub, Slack)
  - Credit card numbers (Visa, Mastercard, AmEx, Discover)
  - Phone numbers (international formats)
  - ID numbers (SSN, passport, driver's license)
  - IP addresses
  - Physical addresses
  - Dates and monetary values
  - Passwords and authentication tokens

## Installation

### Prerequisites

- Python 3.11+

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Anonimizer.git
   cd Anonimizer
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv censor_env

   # Windows
   censor_env\Scripts\activate

   # Linux/macOS
   source censor_env/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Download spaCy model:
   ```bash
   python -m spacy download en_core_web_lg
   ```

## Usage

### Basic Usage

```bash
# Anonymize a document
python main.py --input document.pdf --output anonymized.pdf

# Process Word documents
python main.py --input report.docx --output redacted.docx

# Process Excel files
python main.py --input data.xlsx --output anonymized.xlsx

# Process text/markdown files
python main.py --input notes.md --output censored.md
```

### Configuration

Edit `config.json5` to customize the censoring behavior:

```json5
{
    // Keywords to identify company-specific information
    keywords: [
        "YourCompanyName",
        "ProjectCodename"
    ],

    // Censoring methods: "regex", "offline_model", or both
    censor_type: ["regex", "offline_model"],

    // spaCy model for NLP-based censoring
    censor_model: "en_core_web_lg"
}
```

### Available Models

| Model | Size | Accuracy | Speed |
|-------|------|----------|-------|
| `en_core_web_sm` | Small | Good | Fast |
| `en_core_web_md` | Medium | Better | Moderate |
| `en_core_web_lg` | Large | Best | Slower |

## Project Structure

```
Anonimizer/
├── main.py                      # Entry point
├── config.json5                 # Configuration file
├── requirements.txt             # Python dependencies
├── censor/
│   ├── regex_censor.py         # Regex-based PII detection
│   └── offline_model_censor.py # NLP-based PII detection
├── helpers/
│   ├── arguments_parser.py     # CLI argument handling
│   ├── file_handler.py         # File I/O operations
│   └── logger.py               # Logging configuration
├── models/                      # Pre-downloaded spaCy models
├── tests/                       # Sample test documents
└── logs/                        # Application logs
```

## How It Works

1. **File Detection**: Automatically detects input file format
2. **Content Extraction**: Extracts text while preserving structure
3. **PII Detection**: Applies regex patterns and/or NLP models
4. **Redaction**: Replaces sensitive information with `[REDACTED]` markers
5. **Output**: Reconstructs document in original format

## Supported File Formats

| Format | Extension | Read | Write |
|--------|-----------|------|-------|
| PDF | `.pdf` | ✓ | ✓ |
| Word | `.docx` | ✓ | ✓ |
| Excel | `.xlsx` | ✓ | ✓ |
| CSV | `.csv` | ✓ | ✓ |
| JSON | `.json` | ✓ | ✓ |
| Markdown | `.md` | ✓ | ✓ |
| Text | `.txt` | ✓ | ✓ |
| XML | `.xml` | ✓ | ✓ |
| HTML | `.html` | ✓ | ✓ |

## Dependencies

- **json5** - Configuration parsing with comments
- **pandas** - Data manipulation
- **openpyxl** - Excel file handling
- **python-docx** - Word document processing
- **PyPDF2** - PDF manipulation
- **pdfminer.six** - PDF text extraction
- **spacy** - NLP engine
- **presidio-analyzer** - PII detection
- **presidio-anonymizer** - PII redaction

## License

This project uses the following open-source libraries:

| Library | License |
|---------|---------|
| [spaCy](https://github.com/explosion/spaCy) | MIT |
| [Presidio](https://github.com/microsoft/presidio) | MIT |
| [pandas](https://github.com/pandas-dev/pandas) | BSD-3-Clause |
| [NumPy](https://github.com/numpy/numpy) | BSD-3-Clause |
| [python-docx](https://github.com/python-openxml/python-docx) | MIT |
| [PyPDF2](https://github.com/py-pdf/pypdf) | BSD-3-Clause |
| [pdfminer.six](https://github.com/pdfminer/pdfminer.six) | MIT |
| [openpyxl](https://foss.heptapod.net/openpyxl/openpyxl) | MIT |
| [lxml](https://github.com/lxml/lxml) | BSD-3-Clause |
| [json5](https://github.com/dpranke/pyjson5) | Apache-2.0 |
| [requests](https://github.com/psf/requests) | Apache-2.0 |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 / BSD-3-Clause |

---

Made with privacy in mind.
