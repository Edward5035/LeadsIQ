from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from selectolax.parser import HTMLParser
from urllib.parse import urlparse, urljoin
import re
import time
import json
import random
from bs4 import BeautifulSoup
from collections import Counter
from nltk.util import ngrams
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging



# Flask app setup
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user store (now stores any username dynamically)
users = {}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in users else None

# LEADS GENERATOR

# List of user-agents for randomization
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Function to get random user-agent
def get_random_user_agent():
    return random.choice(user_agents)

# Function to perform a DuckDuckGo search and get URLs
def duckduckgo_search(query):
    search_url = f"https://duckduckgo.com/html/?q={query}"
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://duckduckgo.com",
        "DNT": "1",  # Do Not Track Request Header
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
    }

    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        results = []
        for result in soup.find_all('a', {'class': 'result__a'}):  # Corrected class for DuckDuckGo result links
            title = result.text.strip()
            link = result['href']
            # Filtering and ensuring we get valid links
            if link.startswith('/l/') or link.startswith('/?q='):
                link = urljoin("https://duckduckgo.com", link)  # Resolving relative URLs to full URLs
            results.append({'title': title, 'link': link})

        return results
    except requests.exceptions.RequestException as e:
        print(f"Error during search: {e}")
        return []

# Adding a random delay to avoid bot detection
def random_delay():
    time.sleep(random.uniform(1.5, 3.0))  # Random delay between 1.5 to 3 seconds

# Helper functions for extracting information from a page
def extract_info(page_tree, base_url):
    info = {
        'emails': set(),
        'phone_numbers': set(),
        'addresses': set(),
        'social_media': set(),
        'company_name': None,
    }
    # Patterns for extracting data
    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zAZ0-9.-]+\.[a-zA-Z]{2,}")
    phone_pattern = re.compile(r"\+?\d[\d\s\-\(\)]{7,}\d")
    address_patterns = [
        re.compile(pattern) for pattern in [
            r"\d{1,5}\s[\w\s.,-]{1,100},?\s[A-Z]{2}\s\d{5}",
            r"\d{1,5}\s[\w\s.,-]{1,100},?\s[\w\s.,-]{1,100},?\s[A-Z]{2}\s\d{5}",
            r"\d+\s[\w\s.,-]+\s[\w\s.,-]+,\s\w+\s[A-Z]{2}\s\d{5}",
        ]
    ]
    social_media_domains = {"facebook.com", "twitter.com", "linkedin.com", "instagram.com"}

    page_text = page_tree.body.text()

    # Extract emails, phone numbers, and addresses from text
    info['emails'].update(email_pattern.findall(page_text))
    info['phone_numbers'].update(phone_pattern.findall(page_text)[:2])
    for pattern in address_patterns:
        info['addresses'].update(pattern.findall(page_text))

    # Extract emails from 'mailto' links
    for node in page_tree.css('a[href^=mailto]'):
        email = node.attributes.get('href', '').split(':')[1].split('?')[0]
        info['emails'].add(email)

    # Extract social media links
    for node in page_tree.css('a[href]'):
        href = node.attributes.get('href', '')
        if href and any(domain in href for domain in social_media_domains):
            info['social_media'].add(urljoin(base_url, href))

    # Extract company name from structured data or meta tags
    for node in page_tree.css("script[type='application/ld+json']"):
        try:
            structured_data = json.loads(node.text())
            if "name" in structured_data:
                info['company_name'] = structured_data["name"]
                break
        except json.JSONDecodeError:
            continue

    if not info['company_name']:
        meta_name = page_tree.css_first('meta[property="og:site_name"]')
        if meta_name:
            info['company_name'] = meta_name.attributes.get('content', '')

    # Fallback to domain name if company name is still not found
    if not info['company_name']:
        domain = urlparse(base_url).netloc.split('.')
        if len(domain) > 1:
            business_name = domain[0].replace('www', '').replace('-', ' ').replace('_', ' ').title()
            if business_name.lower() not in ('top', '10', 'forbes', 'yelp', 'houzz', 'tripadvisor', 'angieslist', 'yellowpages', 'bbb'):
                info['company_name'] = business_name

    # Ensure all sets are converted to lists before returning
    return {k: list(v) if isinstance(v, set) else v for k, v in info.items()}

# Function to fetch page content
def fetch_page_content(url, headers):
    try:
        random_delay()
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            page_tree = HTMLParser(response.text)  # Use selectolax's HTMLParser
            return page_tree
        else:
            print(f"Failed to retrieve {url} with status code {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching content from {url}: {e}")
        return None

# Lead generator page route
@app.route('/leads-generator')
@login_required
def leads_generator():
    # Retrieve session data to display
    leads = session.get('leads', [])
    lead_count = session.get('lead_count', 0)
    email_count = session.get('email_count', 0)
    phone_count = session.get('phone_count', 0)
    address_count = session.get('address_count', 0)
    social_media_count = session.get('social_media_count', 0)
    company_name_count = session.get('company_name_count', 0)

    # Render the template and pass data
    return render_template(
        'leads_generator.html',
        title="Leads Generator",
        leads=leads,
        lead_count=lead_count,
        email_count=email_count,
        phone_count=phone_count,
        address_count=address_count,
        social_media_count=social_media_count,
        company_name_count=company_name_count
    )

# Main search route
@app.route('/search', methods=['POST'])
@login_required
def search():
    query = request.form.get('business_type')
    if not query:
        return redirect(url_for('leads_generator'))

    search_results = duckduckgo_search(query)
    leads = []
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://duckduckgo.com",
        "DNT": "1",  # Do Not Track Request Header
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
    }

    # Using ThreadPoolExecutor to fetch data in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}  # Using a dictionary to store futures and their corresponding link_node
        for result in search_results:
            link = result['link']
            future = executor.submit(fetch_page_content, link, headers)
            futures[future] = link  # Store link in the dictionary with future as the key

    # Handle the results
    for future in as_completed(futures):
        page_content = future.result()
        link = futures[future]  # Retrieve the associated link for each future
        if page_content:
            base_url = urljoin(link, '/')
            info = extract_info(page_content, base_url)
            leads.append({
                'link': link,
                'info': info
            })

    # Store leads data in session
    session['leads'] = leads  # Store the leads in session
    session['lead_count'] = len(leads)
    session['email_count'] = sum(len(lead['info'].get('emails', [])) for lead in leads)
    session['phone_count'] = sum(len(lead['info'].get('phone_numbers', [])) for lead in leads)
    session['address_count'] = sum(len(lead['info'].get('addresses', [])) for lead in leads)
    session['social_media_count'] = sum(len(lead['info'].get('social_media', [])) for lead in leads)
    session['company_name_count'] = sum(1 for lead in leads if lead['info'].get('company_name'))

    # Redirect to the leads generator page after updating session
    return redirect(url_for('leads_generator'))



# SEO ---------------------------------------------------------------

# Rotate User Agents
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Function to extract keywords and n-grams
def extract_keywords(text):
    words = re.findall(r'\b\w{3,}\b', text.lower())  # Only words with 3+ characters
    # Generate n-grams (bigrams, trigrams, etc.)
    ngrams_list = sum([[' '.join(gram) for gram in ngrams(words, n)] for n in range(2, 6)], [])
    # Combine words and n-grams
    phrases = words + ngrams_list
    stopwords = set(['the', 'in', 'and', 'or', 'is', 'it', 'to', 'from', 'by', 'with', 'for', 'on', 'at', 'as', 'this', 'that', 'these', 'those', 'i', 'we', 'they', 'you', 'll', 'pm', 'am'])
    return [phrase for phrase in phrases if not any(stopword in phrase for stopword in stopwords)]

def classify_keywords(keywords):
    short_tail = set()
    long_tail = set()
    for keyword in keywords:
        if len(keyword.split()) == 1:
            short_tail.add(keyword)
        else:
            long_tail.add(keyword)
    return short_tail, long_tail

def calculate_percentages(keywords, total):
    return {k: (v / total) * 100 for k, v in keywords.items()}

# Function to make a request with retries, rotating user agents, and realistic headers
def get_request(url):
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": url,
        "Connection": "keep-alive",
        "DNT": "1",  # Do Not Track Request Header
    }

    session = requests.Session()
    session.headers.update(headers)

    try:
        # Simulate human-like behavior by adding random sleep time
        time.sleep(random.uniform(1, 3))  # Random delay between 1 and 3 seconds
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error during request to {url}: {e}")
        return None

# Main route for SEO Boost
@app.route('/seo-boost', methods=['GET', 'POST'])
def seo_boost():
    if request.method == 'POST':
        query = request.form.get('business_name')
        if not query:
            return redirect(url_for('seo_boost'))

        search_terms = ["local business", "near me", "business directory"]
        search_queries = [f"{query} {term}" for term in search_terms]
        businesses = []
        all_keywords = []

        # Create a session for reuse
        session = requests.Session()

        # Function to scrape page and extract keywords
        def process_page(href):
            try:
                page_response = get_request(href)
                if not page_response:
                    return []
                page_soup = BeautifulSoup(page_response, 'html.parser')

                # Extract text from paragraphs, meta descriptions, and headings
                page_text = " ".join([p.get_text() for p in page_soup.find_all(['p', 'meta', 'h1', 'h2', 'h3'])])
                return extract_keywords(page_text)
            except Exception as e:
                print(f"Error scraping {href}: {e}")
                return []

        # Parallelize requests using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for search_query in search_queries:
                # DuckDuckGo search URL
                search_url = f"https://duckduckgo.com/html/?q={search_query}"

                try:
                    response = get_request(search_url)
                    if not response:
                        continue

                    soup = BeautifulSoup(response, 'html.parser')

                    # Adjust for DuckDuckGo's HTML structure
                    for result in soup.find_all('div', class_='result'):
                        link_node = result.find('a', class_='result__a')
                        if link_node:
                            href = link_node['href']
                            domain = urlparse(href).netloc
                            if href and domain:
                                businesses.append({'url': href, 'domain': domain})

                                # Asynchronously scrape the page for keywords
                                futures.append(executor.submit(process_page, href))

                except Exception as e:
                    print(f"Error during DuckDuckGo search scraping: {e}")
                    continue

            # Collect all keywords from page scraping
            for future in as_completed(futures):
                all_keywords.extend(future.result())

        # Count and classify keywords
        keyword_counts = Counter(all_keywords)
        keywords = {k: v for k, v in keyword_counts.items() if v > 1}  # Only include keywords that appear more than once
        total_keywords = sum(keywords.values())
        keyword_percentages = calculate_percentages(keywords, total_keywords)
        short_tail, long_tail = classify_keywords(keywords)

        return render_template('seo_boost.html', title="SEO Boost", short_tail=short_tail, long_tail=long_tail, keyword_percentages=keyword_percentages)
    else:
        return render_template('seo_boost.html', title="SEO Boost", short_tail=[], long_tail=[], keyword_percentages={})



# COMPETITOR ANALYSIS


# Function to perform a DuckDuckGo search and get URLs

# List of user agents for rotation
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Function to make a request with retries, rotating user agents, and realistic headers
def get_request(url):
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": url,
        "Connection": "keep-alive",
        "DNT": "1",  # Do Not Track Request Header
    }

    session = requests.Session()
    retry = Retry(connect=5, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    try:
        # Simulate human-like behavior by adding random sleep time
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error during request to {url}: {e}")
        return None

# Function to perform a DuckDuckGo search using requests and parse the HTML with BeautifulSoup
def duckduckgo_search(query):
    search_url = f"https://duckduckgo.com/html/?q={query}"

    try:
        page_content = get_request(search_url)
        if not page_content:
            return []

        soup = BeautifulSoup(page_content, 'html.parser')

        results = []
        for result in soup.find_all('div', class_='result'):
            title = result.find('a', class_='result__a').get_text()
            link = result.find('a', class_='result__a')['href']
            description = result.find('a', class_='result__snippet').get_text() if result.find('a', class_='result__snippet') else 'No description'

            # Exclude Yelp links
            if 'yelp.com' not in link:
                results.append({'title': title, 'link': link, 'description': description})

        return results
    except Exception as e:
        print(f"Error during DuckDuckGo search: {e}")
        return []

# Function to scrape competitor data from each URL
def scrape_competitor_data(url):
    page_content = get_request(url)
    if not page_content:
        return {'business_name': 'Error', 'description': 'Failed to retrieve data', 'services': ['Error retrieving services']}

    soup = BeautifulSoup(page_content, 'html.parser')
    title = soup.find('title').get_text() if soup.find('title') else 'No title'
    description = soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else 'No description'
    business_name = soup.find('meta', property='og:site_name')['content'] if soup.find('meta', property='og:site_name') else title.split(" - ")[0].strip()

    # Get services
    services = []
    keyword_patterns = ['services', 'our services', 'what we do', 'offerings', 'products', 'solutions']
    for keyword in keyword_patterns:
        for element in soup.find_all(string=lambda text: text and keyword.lower() in text.lower()):
            parent = element.find_parent()
            if parent:
                services.extend([item.get_text().strip() for item in parent.find_all(['li', 'p', 'div']) if item.get_text().strip()])

    if not services:
        services = ['No services available']

    return {
        'business_name': business_name,
        'description': description,
        'services': services
    }

# Function to rank businesses based on a simple rule
def rank_businesses(businesses):
    return sorted(businesses, key=lambda x: (x['description'] != 'No description', len(x['services'])), reverse=True)

# Flask route for competitor analysis
@app.route('/competitor_analysis', methods=['GET', 'POST'])
def competitor_analysis():
    if request.method == 'POST':
        business_type = request.form.get('business_type')
        location = request.form.get('location')

        if not business_type or not location:
            return redirect(url_for('competitor_analysis'))

        query = f"{business_type} {location}"
        try:
            # Perform DuckDuckGo search using requests and BeautifulSoup
            search_results = duckduckgo_search(query)
            print(f"DuckDuckGo Search Results: {search_results}")

            extracted_info = []
            for result in search_results:
                try:
                    real_info = scrape_competitor_data(result['link'])
                    if 'services' in real_info and real_info['business_name'] != 'Error':
                        extracted_info.append(real_info)
                    elif 'services' not in real_info:
                        extracted_info.append({
                            'business_name': real_info.get('business_name', 'Error'),
                            'description': real_info.get('description', 'Failed to retrieve data'),
                            'services': ['No services available due to scraping error']
                        })
                except Exception as e:
                    print(f"Error while scraping URL {result['link']}: {e}")
                    extracted_info.append({
                        'business_name': 'Error',
                        'description': 'Failed to retrieve data',
                        'services': ['Error retrieving services']
                    })
            
            ranked_businesses = rank_businesses(extracted_info)
            print(f"Ranked Businesses: {ranked_businesses}")

            while len(ranked_businesses) < 10:
                ranked_businesses.append({
                    'business_name': 'No business found',
                    'description': 'No description available',
                    'services': ['No services available']
                })

            return render_template('competitor_analysis.html', title="Competitor Analysis", search_results=ranked_businesses)

        except Exception as e:
            print(f"Error during competitor analysis: {e}")
            return render_template('competitor_analysis.html', title="Competitor Analysis", search_results=[])

    return render_template('competitor_analysis.html', title="Competitor Analysis", search_results=[])




#best----------------------------------------------------------------
# LOGIN


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Simplified login to accept any username/password
        if username and password:
            # Add user to the session
            if username not in users:
                users[username] = generate_password_hash(password)
                
            user = User(username)
            login_user(user)

            # Set default session values to 0 for a fresh session
            session['lead_count'] = 0
            session['email_count'] = 0
            session['phone_count'] = 0
            session['address_count'] = 0
            session['social_media_count'] = 0
            session['company_name_count'] = 0
            
            # Redirect to the index or dashboard after login
            return redirect(url_for('dashboard'))
        
        return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logs out the user
    session.clear()  # Clears all session data
    return redirect(url_for('login'))  # Redirects to the login page (or any other page)


#NEW ROUTES-----------–--------------------------------------------

@app.route('/')
def index():
    return render_template('dashboard.html')  # Assuming you have an 'index.html' template


@app.route('/dashboard')
@login_required
def dashboard():
    # Retrieve the qualified_leads_count from the session, defaulting to 0 if not found
    qualified_leads_count = session.get('qualified_leads_count', 0)

    # Render the dashboard template, passing the qualified_leads_count
    return render_template('dashboard.html', 
                           title="Smart Overview", 
                           qualified_leads_count=qualified_leads_count)


@app.route('/leads-generator', endpoint='unique_leads_generator')
@login_required
def leads_generator():
    # Your function logic here
    return render_template('leads_generator.html', title="Leads Generator")



# SALES SECTION------------------


# sales-trends-----------
@app.route('/sales_trends')
def sales_trends():
    return render_template('sales_trends.html')




# sales-analyzer--------------

@app.route('/sales-analyze')
def sales_analyzer():
    return render_template('sales_analyze.html')






# email-accelerator---------------------

@app.route('/email-growth-engine')
def email_growth_engine():
    return render_template('email_growth_engine.html')





# Ad_Campaign_Booster-----------------------

@app.route('/Ad-Campaign-Booster')
def Ad_Campaign_Booster():
    return render_template('Ad_Campaign_Booster.html')



# help-support----------------

@app.route('/help-support')
def help_support():
    return render_template('help_support.html')

# NEW FEATURES-------------------------------------------------------------------------------------------------------


# Contact Info-------------------------------------------------------------------------------------------------------



# Rotate User Agents to avoid detection
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Function to make a request with retries, rotating user agents, and realistic headers
def get_request(url):
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": url,
        "Connection": "keep-alive",
        "DNT": "1",  # Do Not Track Request Header
    }

    session = requests.Session()
    session.headers.update(headers)

    try:
        # Simulate human-like behavior by adding random sleep time
        time.sleep(random.uniform(1, 3))  # Random delay between 1 and 3 seconds
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error during request to {url}: {e}")
        return None

# Function to scrape DuckDuckGo search results
def scrape_duckduckgo_search(query):
    search_url = f"https://duckduckgo.com/html?q={query}"
    response = get_request(search_url)
    if not response:
        return []
    
    soup = BeautifulSoup(response, 'html.parser')
    results = []

    for result in soup.find_all('div', class_='result'):
        title = result.find('a', class_='result__a').get_text() if result.find('a', class_='result__a') else 'No title'
        link = result.find('a', class_='result__a')['href'] if result.find('a', class_='result__a') else 'No link'
        domain = urlparse(link).netloc
        description = result.find('a', class_='result__snippet').get_text() if result.find('a', class_='result__snippet') else 'No description'

        # Filter out results that seem like lists or directories
        if "best" not in title.lower() and "directory" not in title.lower() and "list" not in title.lower() and "to know" not in title.lower() and "near me" not in title.lower():
            if "yelp.com" not in domain and "tripadvisor.com" not in domain and "houzz.com" not in domain:
                results.append({
                    'title': title,
                    'link': link,
                    'domain': domain,
                    'description': description
                })
    
    return results

# Function to extract contact information
def extract_contact_info(soup):
    contact_info = {}

    # Try to find email addresses
    email = None
    for a in soup.find_all('a', href=True):
        if 'mailto:' in a['href']:
            email = a['href'].replace('mailto:', '')
            break
    
    if not email:
        email = 'No email'

    # Try to find phone numbers
    phone = None
    for a in soup.find_all('a', href=True):
        if 'tel:' in a['href']:
            phone = a['href'].replace('tel:', '')
            break
    
    if not phone:
        phone = 'No phone'

    # Try to find addresses in different common classes
    address = None
    address_classes = ['address', 'contact-address', 'location', 'footer-address']
    for class_name in address_classes:
        address_tag = soup.find('div', class_=class_name) or soup.find('span', class_=class_name) or soup.find('p', class_=class_name)
        if address_tag:
            address = address_tag.get_text().strip()
            break

    if not address:
        address = 'No address'

    contact_info['email'] = email
    contact_info['phone'] = phone
    contact_info['address'] = address
    return contact_info

# Function to get detailed information from a page
def get_real_info(url, session):
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extracting business name
        business_name = soup.find('meta', property='og:site_name')
        if business_name:
            business_name = business_name['content']
        else:
            business_name = soup.find('title').get_text().split(" - ")[0].strip()

        # Extracting contact information
        contact_info = extract_contact_info(soup)

        return {
            'business_name': business_name,
            'contact_info': contact_info
        }
    except requests.exceptions.Timeout as e:
        return {'business_name': 'Error', 'contact_info': {'email': 'N/A', 'phone': 'N/A', 'address': 'N/A'}, 'services': str(e)}
    except requests.exceptions.RequestException as e:
        return {'business_name': 'Error', 'contact_info': {'email': 'N/A', 'phone': 'N/A', 'address': 'N/A'}, 'services': str(e)}

# Flask route for contact information
@app.route('/contact_info', methods=['GET', 'POST'])
def contact_info():
    if request.method == 'POST':
        business_type = request.form.get('business_type')
        location = request.form.get('location')
        if not business_type or not location:
            return redirect(url_for('contact_info'))

        query = f"{business_type} {location}"
        search_results = scrape_duckduckgo_search(query)

        session = requests.Session()
        retry = Retry(connect=5, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        extracted_info = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(get_real_info, result['link'], session): result for result in search_results}

            for future in as_completed(futures):
                real_info = future.result()
                if real_info['business_name'] != 'Error':
                    extracted_info.append(real_info)

        return render_template('contact_info.html', title="Contact Information", search_results=extracted_info)

    return render_template('contact_info.html', title="Contact Information", search_results=[])

#EMAIL SENDER


# Function to send an email
def send_email(smtp_server, port, sender_email, password, receiver_email, subject, body):
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

# Flask route for mass outreach
@app.route('/mass_outreach', methods=['GET', 'POST'])
def mass_outreach():
    if request.method == 'POST':
        sender_email = request.form.get('sender_email')
        password = request.form.get('password')
        subject = request.form.get('subject')
        body = request.form.get('body')
        recipient_emails = request.form.get('recipient_emails').split(',')

        smtp_server = "smtp.gmail.com"
        port = 587

        for receiver_email in recipient_emails:
            send_email(smtp_server, port, sender_email, password, receiver_email.strip(), subject, body)

        return redirect(url_for('mass_outreach_success'))

    return render_template('mass_outreach.html')

@app.route('/mass_outreach_success')
def mass_outreach_success():
    return "Emails sent successfully!"




# Rotate User Agents to avoid detection
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Function to make a request with retries, rotating user agents, and realistic headers
def get_request(url):
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": url,
        "Connection": "keep-alive",
        "DNT": "1",  # Do Not Track Request Header
    }

    session = requests.Session()
    session.headers.update(headers)

    try:
        # Simulate human-like behavior by adding random sleep time
        time.sleep(random.uniform(1, 3))  # Random delay between 1 and 3 seconds
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error during request to {url}: {e}")
        return None

# Function to scrape DuckDuckGo search results for social media handles
def scrape_duckduckgo_search(handle):
    search_url = f"https://duckduckgo.com/html?q={handle} site:linkedin.com OR site:twitter.com OR site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:pinterest.com OR site:youtube.com"
    response = get_request(search_url)
    if not response:
        return []
    
    soup = BeautifulSoup(response, 'html.parser')
    leads = []

    for g in soup.find_all('div', class_='result'):
        link_node = g.find('a', class_='result__a')
        description_node = g.find('a', class_='result__snippet')

        if link_node:
            profile_url = link_node['href']
            if any(platform in profile_url for platform in ['linkedin.com', 'twitter.com', 'instagram.com', 'facebook.com', 'tiktok.com', 'pinterest.com', 'youtube.com']):
                leads.append({
                    'social_media_handle': handle,
                    'profile_url': profile_url
                })
    
    return leads

@app.route('/social-scout', methods=['GET', 'POST'])
@login_required
def social_scout():
    if request.method == 'POST':
        handle = request.form.get('social_media_handle')
        if not handle:
            return redirect(url_for('social_scout'))

        # Scrape DuckDuckGo instead of Google for social media profiles
        leads = scrape_duckduckgo_search(handle)

        return render_template('social_scout.html', title="Social Media Search", leads=leads)

    return render_template('social_scout.html', title="Social Media Search")

# Lead validation

def score_lead(lead_info):
    """
    Generates a score, category, and conversion rate for a lead based on various criteria.
    :param lead_info: A dictionary containing lead details (name, emails, phone_numbers, address, social_media).
    :return: A dictionary with the score, category, and conversion rate for the lead.
    """
    score = 0

    # Scoring based on the number of emails
    if 'emails' in lead_info and lead_info['emails']:
        score += len(lead_info['emails']) * 10

    # Scoring based on the number of phone numbers
    if 'phone_numbers' in lead_info and lead_info['phone_numbers']:
        score += len(lead_info['phone_numbers']) * 5

    # Scoring based on presence of an address
    if 'address' in lead_info and lead_info['address'] and lead_info['address'] != 'None':
        score += 15

    # Scoring based on the number of social media links
    if 'social_media' in lead_info and lead_info['social_media']:
        score += len(lead_info['social_media']) * 10

    # Determine category based on score
    if score >= 50:
        category = 'High'
        conversion_rate = 90
    elif 30 <= score < 50:
        category = 'Medium'
        conversion_rate = 60
    else:
        category = 'Low'
        conversion_rate = 30

    return {
        'score': score,
        'category': category,
        'conversion_rate': conversion_rate
    }


@app.route('/ai-lead-scoring', methods=['GET', 'POST'])
@login_required
def ai_lead_scoring():
    results = []
    if request.method == 'POST':
        # Get leads from form
        leads_text = request.form.get('leads', '')
        file = request.files.get('file')

        if file:
            leads_text = file.read().decode('utf-8')

        if leads_text.strip():
            # Simulate AI processing delay
            delay = random.uniform(2, 5)
            time.sleep(delay)

            # Parse the leads
            lead_infos = parse_leads(leads_text)

            # Process each lead
            for lead_info in lead_infos:
                score_info = score_lead(lead_info)
                score_info['score'] += random.randint(-5, 5)  # Add variability
                ai_feedback = f"AI has determined that the lead '{lead_info.get('name', 'No Name')}' has a {score_info['category']} potential."

                results.append({
                    'name': lead_info.get('name', 'No Name'),
                    'score': score_info['score'],
                    'category': score_info['category'],
                    'conversion_rate': score_info['conversion_rate'],
                    'email': ', '.join(lead_info.get('emails', [])),
                    'phone': ', '.join(lead_info.get('phone_numbers', [])),
                    'address': lead_info.get('address', 'None'),
                    'social_media': ', '.join(lead_info.get('social_media', [])),
                    'ai_feedback': ai_feedback
                })

    # Render the template with results
    return render_template('ai_lead_scoring.html', results=results)

def parse_leads(leads_text):
    """Mock function to parse leads from text."""
    # Example implementation (to be replaced with real parsing logic)
    return [
        {'name': 'John Doe', 'emails': ['john@example.com'], 'phone_numbers': ['123-456-7890'], 'address': '123 Main St', 'social_media': ['@johndoe']}
    ]

def score_lead(lead_info):
    """Mock function to score leads."""
    # Example scoring logic
    return {
        'score': random.randint(50, 100),
        'category': 'High' if random.random() > 0.5 else 'Medium',
        'conversion_rate': random.uniform(5, 15)
    }







# Lead Qualifier



# Function to qualify a lead based on criteria
def qualify_lead(lead_info):
    """
    Qualifies a lead based on certain criteria such as emails, phone numbers, address, and social media presence.
    :param lead_info: A dictionary containing lead details (company_name, emails, phone_numbers, address, social_media).
    :return: A dictionary with qualification status (High, Medium, Low) and other details.
    """
    score = 0
    qualification_status = ''

    # Qualifying based on the number of emails
    if 'emails' in lead_info and lead_info['emails']:
        score += len(lead_info['emails']) * 10

    # Qualifying based on the number of phone numbers
    if 'phone_numbers' in lead_info and lead_info['phone_numbers']:
        score += len(lead_info['phone_numbers']) * 5

    # Qualifying based on presence of an address
    if 'address' in lead_info and lead_info['address']:
        score += 20

    # Qualifying based on the number of social media links
    if 'social_media' in lead_info and lead_info['social_media']:
        score += len(lead_info['social_media']) * 10

    # Determine qualification status based on score
    if score >= 50:
        qualification_status = 'High'
    elif 30 <= score < 50:
        qualification_status = 'Medium'
    else:
        qualification_status = 'Low'

    # Return the result with qualification status
    return {
        'score': score,
        'qualification_status': qualification_status,
        'conversion_rate': 100 if qualification_status == 'High' else (60 if qualification_status == 'Medium' else 30),
        'ai_feedback': f"The lead has a {qualification_status} qualification potential."
    }

# Example mock function to parse leads from text or file

def parse_leads(leads_text):
    """Function to parse leads from the raw text input."""
    leads = []
    
    # Split the text by the 'Visit Website' or other relevant separator to get individual lead entries.
    lead_entries = leads_text.split('Visit Website')
    
    for entry in lead_entries:
        # Initialize lead data
        lead_info = {
            'company_name': None,
            'emails': [],
            'phone_numbers': [],
            'address': [],
            'social_media': []
        }
        
        # Extract company name - we’ll grab everything before "Email" or "Phone"
        company_name_match = re.match(r'^(.*?)(?:\n|Email:)', entry.strip())
        if company_name_match:
            lead_info['company_name'] = company_name_match.group(1).strip()

        # Extract emails using regex to match email patterns
        email_matches = re.findall(r'[\w\.-]+@[\w\.-]+', entry)
        lead_info['emails'] = email_matches
        
        # Extract phone numbers (basic regex for various phone formats)
        phone_matches = re.findall(r'\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}', entry)
        lead_info['phone_numbers'] = phone_matches
        
        # Extract addresses by looking for lines that contain the address information
        address_matches = re.findall(r'\d+\s[\w\s]+(?:St\.|Ave\.|Blvd|Rd|Dr|Pl|Lane|Ct|Way|[A-Za-z]{2,})', entry)
        lead_info['address'] = address_matches
        
        # Extract and clean social media links
        social_media_matches = re.findall(r'https?://(?:www\.)?[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]+', entry)
        lead_info['social_media'] = social_media_matches
        
        leads.append(lead_info)
    
    return leads

@app.route('/ai-lead-qualification', methods=['GET', 'POST'])
@login_required
def ai_lead_qualification():
    results = []
    # Reset the qualified_leads_count to 0 after every login (session reset).
    session['qualified_leads_count'] = 0  # Ensure it starts from 0 on every login.

    # Initialize the count from the session
    qualified_leads_count = session['qualified_leads_count']

    if request.method == 'POST':
        # Get leads from form submission
        leads_text = request.form.get('leads', '')
        file = request.files.get('file')

        if file:
            leads_text = file.read().decode('utf-8')

        if leads_text.strip():
            # Simulate AI processing delay
            delay = random.uniform(2, 5)
            time.sleep(delay)

            # Parse the leads
            lead_infos = parse_leads(leads_text)

            # Process each lead for qualification
            for lead_info in lead_infos:
                qualification_info = qualify_lead(lead_info)

                # Check qualification status and count qualified leads with a score >= 70
                if qualification_info['score'] >= 70:  # Adjust this line to count leads with score >= 70
                    qualified_leads_count += 1

                # Append the results including the company name
                results.append({
                    'company_name': lead_info.get('company_name', 'No Company Name'),
                    'score': qualification_info['score'],
                    'qualification_status': qualification_info['qualification_status'],
                    'conversion_rate': qualification_info['conversion_rate'],
                    'email': ', '.join(lead_info.get('emails', [])) or 'N/A',
                    'phone': ', '.join(lead_info.get('phone_numbers', [])) or 'N/A',
                    'address': ', '.join(lead_info.get('address', [])) or 'N/A',
                    'social_media': ', '.join(lead_info.get('social_media', [])) or 'N/A',
                    'ai_feedback': qualification_info['ai_feedback']
                })

        # Store the updated qualified leads count in the session
        session['qualified_leads_count'] = qualified_leads_count
    
    return render_template('ai_lead_qualification.html', results=results, qualified_leads_count=qualified_leads_count)


if __name__ == '__main__':
    app.run(threaded=True)
