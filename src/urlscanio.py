import os
import yaml
import requests
import time
import json

from stix2 import (
    Bundle,
    AttackPattern,
    Relationship,
    File,
    TLP_WHITE,
)
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
)


class Urlscanio:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_key = get_config_variable(
            "URLSCANIO_API_KEY", ["urlscanio", "api_key"], config
        )

        self.max_tlp = get_config_variable(
            "URLSCANIO_MAX_TLP", ["urlscanio", "max_tlp"], config
        )


    def _send_knowledge(self, observable, report):

        final_observable = observable
        ob_id=final_observable["standard_id"]
        verdict = report.get('verdicts')
        if verdict is not None:
            overall = verdict.get('overall')
            malicious = overall.get('malicious')
            if malicious == True :
                tag_ha = self.helper.api.label.create(value="Malicious", color="#f44336")
                self.helper.api.stix_cyber_observable.add_label(
                    id=ob_id, label_id=tag_ha["id"]
                )
                lists = report.get('lists')
                if lists is not None:
                    countries = lists.get('countries')
                    for c in countries:
                        tag_c = self.helper.api.label.create(value=c, color="#ffff00")
                        self.helper.api.stix_cyber_observable.add_label(
                            id=ob_id, label_id=tag_c["id"]
                        )
            score = overall.get('score')
            urlscan_verdict = verdict.get('urlscan')
            categories = urlscan_verdict.get('categories')
            #Aggiungo i labels alla pagina
            for tag in categories:
                tag_ha = self.helper.api.label.create(value=tag, color="#0059f7")
                self.helper.api.stix_cyber_observable.add_label(
                    id=ob_id, label_id=tag_ha["id"]
                )
        else :
            score=0
        task = report.get('task')
        reportURL = task['reportURL']
        if reportURL is None:
            return "Url, IP, hostname analizzato non valido "
        screen = task["screenshotURL"]
        self.helper.log_info("Errore dovuto a un campo preso da json")

        #Metto nella descrizione le statistiche
        stats = report.get('stats')
        secureRequest = stats.get('secureRequests')
        securePercentage = stats.get('securePercentage')
        IPv6Percentage = stats.get('IPv6Percentage')
        uniqCountries = stats.get('uniqCountries')
        totalLinks = stats.get('totalLinks')
        adBlocked = stats.get('adBlocked')
        stringa ="secure request:"+str(secureRequest)+", secure percentage:" + str(securePercentage) +", IPv6 percentage:" +str(IPv6Percentage)+", uniq countries:"+str(uniqCountries)+", total links:" + str(totalLinks)+", adBlocker:" + str(adBlocked)
        #Aggiorno lo score
        
        self.helper.api.stix_cyber_observable.update_field(
            id=ob_id,
            input={"key": "x_opencti_score", "value": str(score)},

        )
        #Aggiungo statistiche nella descrizione
        self.helper.api.stix_cyber_observable.update_field(
            id=ob_id,
            input={"key": "x_opencti_description", "value": stringa},

        )
        # Create external reference report
        external_reference = self.helper.api.external_reference.create(
            source_name="Urlscan.io",
            url= reportURL ,
            description="Report di Urlscan.io",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=ob_id,
            external_reference_id=external_reference["id"],
        )
        #Create external reference screen shot
        external_reference = self.helper.api.external_reference.create(
            source_name="Screen Shot",
            url= screen ,
            description="Screen Shot di Urlscan.io",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=ob_id,
            external_reference_id=external_reference["id"],
        )



    def _submit_url(self, observable):
        self.helper.log_info("Observable is a URL, triggering the sandbox...")
        values = observable["value"]
        
        headers = {'API-Key': self.api_key ,'Content-Type':'application/json'}
        data = {"url": values, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
        res = response.json()
        api = res.get('api')
        time.sleep(15)
        html = requests.get(api).text
        data = json.loads(html)

        self._send_knowledge(observable, data)



    def _process_observable(self, observable):
        self.helper.log_info(
            "Processing the observable " + observable["observable_value"]
        )

        if observable["entity_type"] in ["Url","IPv4-Addr","IPv6-Addr","X-OpenCTI-Hostname", "Domain-Name"]:
            return self._submit_url(observable)


    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable non trovato :  "
                "(forse è linked a data seggregation, controlla il tuo group e permissions)"
            )
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)




if __name__ == "__main__":
    try:
        urlscanio = Urlscanio()
        urlscanio.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)