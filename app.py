# from flask import Flask, request, render_template, url_for
# import pickle
# import numpy as np
# import json
# import requests

# app = Flask(__name__)
# with open('Phishing_model.pkl', 'rb') as file:
#     model = pickle.load(file)

# @app.route("/")
# def f():
#     return render_template("index.html")

# @app.route("/inspect")
# def inspect():
#     return render_template("inspect.html")


# @app.route("/output", methods=["GET", "POST"])
# def output():
#     if request.method == 'POST':
#         var1 = request.form["UsingIP"]
#         var2 = request.form["PrefixSuffix-"]
#         var3 = request.form["SubDomains"]
#         var4 = request.form["HTTPS"]
#         var5 = request.form["NonStdPort"]
#         var6 = request.form["HTTPSDomainURL"]
#         var7 = request.form["RequestURL"]
#         var8 = request.form["AnchorURL"]
#         var9 = request.form["LinksInScriptTags"]
#         var10 = request.form["ServerFormHandler"]
#         var11 = request.form["InfoEmail"]
#         var12 = request.form["AbnormalURL"]
#         var13 = request.form["WebsiteForwarding"]
#         var14 = request.form["StatusBarCust"]
#         var15 = request.form["DisableRightClick"]
#         var16 = request.form["AgeofDomain"]
#         var17 = request.form["DNSRecording"]
#         var18 = request.form["WebsiteTraffic"]
#         var19 = request.form["PageRank"]
#         var20 = request.form["GoogleIndex"]
#         var21 = request.form["StatsReport"]

#         # Convert the input data into a numpy array
#         predict_data = np.array([var1, var2, var3, var4, var5, var6, var7, var8, var9, var10, 
#                                  var11, var12,var13,var14,var15,var16,var17,var18,var19,var20,var21]).reshape(1, -1)
#         # Use the loaded model to make predictions
#         predict = model.predict(predict_data)

#         if (predict == 1):
#             return render_template('output.html', predict="safe")
#         elif (predict == -1):
#             return render_template('output.html', predict= "Not safe")
#         else:
#             return render_template('output.html', predict="Suspicious")
#     return render_template("output.html")

# if __name__ == "__main__":
#     app.run(debug=False)


from flask import Flask, request, render_template, url_for, jsonify
import pickle
import numpy as np
import json
import requests
from url_analyzer import analyze_url

app = Flask(__name__)

# Load the model
try:
    with open('Phishing_model.pkl', 'rb') as file:
        model = pickle.load(file)
except FileNotFoundError:
    print("Error: Phishing_model.pkl not found!")
    model = None

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/inspect")
def inspect():
    return render_template("Inspect.html")

@app.route("/output", methods=["GET", "POST"])
def output():
    if request.method == 'POST':
        try:
            # Get form data and convert to integers
            var1 = int(request.form.get("UsingIP", 0))
            var2 = int(request.form.get("PrefixSuffix-", 0))
            var3 = int(request.form.get("SubDomains", 0))
            var4 = int(request.form.get("HTTPS", 0))
            var5 = int(request.form.get("NonStdPort", 0))
            var6 = int(request.form.get("HTTPSDomainURL", 0))
            var7 = int(request.form.get("RequestURL", 0))
            var8 = int(request.form.get("AnchorURL", 0))
            var9 = int(request.form.get("LinksInScriptTags", 0))
            var10 = int(request.form.get("ServerFormHandler", 0))
            var11 = int(request.form.get("InfoEmail", 0))
            var12 = int(request.form.get("AbnormalURL", 0))
            var13 = int(request.form.get("WebsiteForwarding", 0))
            var14 = int(request.form.get("StatusBarCust", 0))
            var15 = int(request.form.get("DisableRightClick", 0))
            var16 = int(request.form.get("AgeofDomain", 0))
            var17 = int(request.form.get("DNSRecording", 0))
            var18 = int(request.form.get("WebsiteTraffic", 0))
            var19 = int(request.form.get("PageRank", 0))
            var20 = int(request.form.get("GoogleIndex", 0))
            var21 = int(request.form.get("StatsReport", 0))

            # Convert the input data into a numpy array
            predict_data = np.array([var1, var2, var3, var4, var5, var6, var7, var8, var9, var10, 
                                     var11, var12, var13, var14, var15, var16, var17, var18, var19, var20, var21]).reshape(1, -1)
            
            # Use the loaded model to make predictions
            predict = model.predict(predict_data)[0]

            if predict == 1:
                result = "Safe"
            elif predict == -1:
                result = "Not Safe"
            else:
                result = "Suspicious"
            
            return render_template('output.html', predict=result)
        except Exception as e:
            return render_template('output.html', predict=f"Error: {str(e)}")
    
    return render_template("output.html")

@app.route("/analyze_url", methods=["POST"])
def analyze_url_endpoint():
    """Analyze a URL directly and return prediction."""
    try:
        data = request.get_json()
        url = data.get("url", "").strip()
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Extract features from URL
        features = analyze_url(url)
        
        # Convert to numpy array in the correct order
        feature_order = [
            "UsingIP", "PrefixSuffix-", "SubDomains", "HTTPS", "NonStdPort",
            "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
            "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
            "StatusBarCust", "DisableRightClick", "AgeofDomain", "DNSRecording",
            "WebsiteTraffic", "PageRank", "GoogleIndex", "StatsReport"
        ]
        
        feature_values = [features[f] for f in feature_order]
        predict_data = np.array(feature_values).reshape(1, -1)
        
        # Make prediction
        if model is None:
            return jsonify({"error": "Model not loaded"}), 500
        
        predict = model.predict(predict_data)[0]
        
        if predict == 1:
            result = "Safe"
        elif predict == -1:
            result = "Not Safe"
        else:
            result = "Suspicious"
        
        return jsonify({
            "url": url,
            "prediction": result,
            "features": features
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
    
    