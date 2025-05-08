from flask import Flask, render_template, request, url_for, redirect

app = Flask(__name__)

magic_bytes = b"\x7fELF"

@app.route("/", methods = ["GET", "POST"])
def main():
    if request.method == "POST":
        print("Received something!")
        file = request.files.get('file')

        if file and file.read(4) == magic_bytes: #Valid ELF
            print("Received vali ELF file: ", file.filename)
            return(redirect(url_for("code_analysis")))
        else:
            return render_template("index.html", error = "Invalid file format!")
    return render_template("index.html")



@app.route("/analysis")
def code_analysis():


    
    return render_template("code_analysis.html")