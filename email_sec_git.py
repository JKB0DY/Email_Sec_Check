
from logging import exception

import dns.resolver
from fpdf import FPDF


# Initalizes the remaining functions and takes care of the problem-free operation of these functions.
def main():
    domain, selector = getInputData()
    SPF_answer, spf_data = SPFrecord(domain)
    DKIM_answer, dkim_data = DKIMrecord(domain, selector)
    DMARC_answer, dmarc_data = DMARCrecord(domain)

    s = input("do you want to create a Report document? (Y/N):  ")
    if s == "Y" or s == "y":
        spf_data, spf_version, dkim_version, dmarc_version = dataProcessing(
            spf_data, str(dkim_data), dmarc_data)
        PDF_report(domain, SPF_answer, spf_data, spf_version, DKIM_answer,
                   dkim_version, DMARC_answer, dmarc_version)


# Checks if the domain is existing and if the specified argument has the correct data type.
def getInputData():
    try:
        domain = str(
            input("What is the name of the domain you want to check : "))
        selector = str(
            input("What is the selector for the given domain (If you dont know it, press Enter) : "))

    except KeyboardInterrupt:
        exit()

    if type(domain) == str:
        try:
            dns.resolver.resolve(domain, "MX")

        except Exception:
            print("\n\nThis domain has no MX record, so either you spelled it wrong, the domain doesn't have a mail-server or the DNS is misconfigured.")
            getInputData()

    else:
        print("\n\nPlease enter a valid domain.")
        getInputData()

    return domain, selector


# Checks if the Domain has a TXT-Record specifing the version of spf (v=spf"the version number")
def SPFrecord(domain):
    spf_data = None
    try:
        DNS_record = dns.resolver.resolve(domain, "TXT")

        for DNS_Data in DNS_record:
            if "v=spf" in DNS_Data.to_text():
                state = True
                spf_data = DNS_Data.to_text()

                if "+all" in spf_data:
                    addText = ", but everyone is authorised to send via this domain. (+all)"

                if "-all" in spf_data:
                    addText = "and every email that isn't from an authorised IP is going to be rejected by your email-provider. (-all)"

                if "~all" in spf_data:
                    addText = "and every email that isn't from an authorised IP is going to be marked as suspicius (or is going into quarantine) by your email-provider. (~all)"

                if "?all" in spf_data:
                    addText = ", but everyone is seen as neutral by your email-provider and therefore legit. (?all)"

                SPF_answer = str("The domain " + domain
                                 + " has a spf record " + addText)

        if state != True:
            SPF_answer = str("The domain " + domain + " has no spf record.")

    except dns.resolver.NoAnswer:
        SPF_answer = str("The domain " + domain + " has no spf record.")
        pass

    print("\n\n" + SPF_answer)
    return SPF_answer, spf_data


# Checks if the Domain has a TXT-Record at "selector"._domainkey."domain"
def DKIMrecord(domain, selector):
    dkim_data = None
    if selector != "":
        try:
            DKIM_domain = selector + "._domainkey." + domain
            dns_record = dns.resolver.resolve(DKIM_domain, "TXT")

            for dns_data in dns_record:
                if 'DKIM1' in dns_data.to_text():
                    dkim_data = dns_data.to_text()

            DKIM_answer = str("The domain " + domain
                              + " has a DKIM record, whether its fully deployed is Unknown.")

        except dns.resolver.NoAnswer:
            DKIM_answer = str("A known bug occured")
            pass

        except dns.resolver.NXDOMAIN:
            DKIM_answer = str("The domain " + domain + " has no DKIM record.")
            pass
    else:
        DKIM_answer = str("Weather the domain " + domain +
                          " has a DKIM record is unkown, because you didn't provide a selector")

    print(DKIM_answer)
    return DKIM_answer, dkim_data


# Checks if the Domain has a TXT-Record at _dmarc."domain"
def DMARCrecord(domain):
    dmarc_data = None
    try:
        DMARC_domain = "_dmarc." + domain
        dns_record = dns.resolver.resolve(DMARC_domain, "TXT")

        for dns_data in dns_record:
            if "DMARC1" in dns_data.to_text():
                state = True
                dmarc_data = dns_data.to_text()

                if "p=none" in dmarc_data:
                    state = False
                    DMARC_answer = str("The domain " + domain
                                       + " doesn't use DMARC properly, every mail is checked but either even if the check fails the email is going to be in your inbox.")

                if "p=quarantine" in dmarc_data:
                    addText = "and an email that faild this check, is going to be in quarantine or marked as suspicius."

                if "p=reject" in dmarc_data:
                    addText = "and an email that faild this check, is going to be rejected by your Email provider."

            if state == True:
                DMARC_answer = str("The domain " + domain +
                                   " has a DMARC record " + addText)

    except Exception:
        DMARC_answer = str("The domain " + domain +
                           " has no DNS record for DMARC.")
        pass

    print(DMARC_answer)
    return DMARC_answer, dmarc_data


# Prepares the collected dns entries in order to display them more systematically.
def dataProcessing(spf_data, dkim_data, dmarc_data):
    # manipulates the dns entries so that only the versions are stored.
    if spf_data != None:
        spf_version = spf_data
        spf_version = ((spf_version.split(" ", 1))[0].split("="))[1]

    else:
        spf_version = None

    if dkim_data != None:
        dkim_version = ((dkim_data.split("; ", 1))[0].split("="))[1]

    else:
        dkim_version = None

    if dmarc_data != None:
        dmarc_version = ((dmarc_data.split("; ", 1))[0].split("="))[1]

    else:
        dkim_version = None

    # lists all authorized IPs by going through every single characterchain (spaced by whitespaces) and checking if it is an entry for an authorized IP /Domain
    if spf_data != None:
        spf_data = spf_data.split()
        liste = []

        for text in spf_data:
            if "ip4:" in text or "ip6:" in text or "include:" in text or "a:" in text or "mx:" in text:
                text = (text.split(":"))[1]
                liste.append(text)

        spf_data = liste

    return spf_data, spf_version, dkim_version, dmarc_version


# Creating the PDF report
def PDF_report(domain, SPF_answer, spf_data, spf_version, DKIM_answer, dkim_version, DMARC_answer, dmarc_version):
    # change the string If you want to insert another logo (link or file path) in jpg or png format
    picture = "data:image/png;base64,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"
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("helvetica", "b", 20)
    pdf.image(picture, x=55)
    pdf.ln(4)
    pdf.cell(0, 10, "Email Security Report", "B", align="C")

    pdf.set_font("helvetica", "", 16)
    pdf.ln(20)
    pdf.cell(40, 10, "The inspection of the domain \"" +
                     domain + "\", has revealed:")
    pdf.ln(17)
    pdf.write(7, "SPF: " + SPF_answer)
    pdf.ln(17)
    pdf.write(7, "DKIM: " + DKIM_answer)
    pdf.ln(17)
    pdf.write(7, "DMARC: " + DMARC_answer)

    # page for a detailed display of the data
    pdf.add_page()
    pdf.set_font("helvetica", "b", 20)
    pdf.cell(0, 10, "Details", "B", align="C")
    pdf.set_font("helvetica", "", 16)

    if spf_version != None:
        pdf.ln(20)
        pdf.write(7, "Version of SPF: " + spf_version)

    if dkim_version != None:
        pdf.ln(10)
        pdf.write(7, "Version of DKIM: " + dkim_version)

    if dmarc_version != None:
        pdf.ln(10)
        pdf.write(7, "Version of DMARC: " + dmarc_version)

    if spf_data != None:
        pdf.ln(10)
        pdf.write(7, "The following Ip addresses and servers, mentioned in the spf records of the domains, are authorized to send emails via this domain.")
        pdf.ln(7)

        for text in spf_data:
            pdf.write(7, text)
            pdf.ln(7)

    pdf.output(domain + "_Emailsec.pdf")


if __name__ == "__main__":
    main()
