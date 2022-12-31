import sys

from fingerprint_modify import Fingerprint
from algo_modify import analyse_scenario_result, ml_based
from algo_modify import simple_eckersley, rule_based, split_data, train_ml
from utils_modify import get_unkonwn_fp, get_fp_experiments
import warnings

CONSISTENT_IDS = "getids"
REPLAY_ECKERSLEY = "replayeck"
AUTOMATE_REPLAYS = "auto"
RULE_BASED = "rules"
ML_BASED = "ml"
AUTOMATE_ML = "automl"

ALGO_NAME_TO_FUNCTION = {
    "eckersley": simple_eckersley,
    "rulebased": rule_based,
}

def main(argv):
    warnings.filterwarnings('ignore')
    if argv[0] == CONSISTENT_IDS:
         pass
    #     print("Fetching consistent user ids.")
    #     user_id_consistent = get_consistent_ids(cur)
    #     print("Here.")
    #     with open("./data/consistent_extension_ids.csv", "w") as f:
    #         f.write("user_id\n")
    #         for user_id in user_id_consistent:
    #             f.write(user_id+"\n")


    elif argv[0] == AUTOMATE_ML:
        #print("Start automating ml based scenario")
        exp_name = argv[1]
        algo_matching_name = "hybridalgo"
        nb_min_fingerprints = int(argv[2])
        exp_name += "-%s-%d" % (algo_matching_name, nb_min_fingerprints)

        attributes = Fingerprint.INFO_ATTRIBUTES + Fingerprint.HTTP_ATTRIBUTES + \
                     Fingerprint.JAVASCRIPT_ATTRIBUTES + Fingerprint.FLASH_ATTRIBUTES
        mongo_attributes = Fingerprint.MONGO_ATTRIBUTES

        #print("Begin ml connection")
        #print("Start fetching fingerprints...")
        #fingerprint_dataset = get_fingerprints_experiments(cur, nb_min_fingerprints, attributes)
        fingerprint_dataset = get_fp_experiments(nb_min_fingerprints,mongo_attributes)
        #print("Fetched %d fingerprints." % len(fingerprint_dataset))
        train_data, test_data = split_data(0.70, fingerprint_dataset)
        model = train_ml(fingerprint_dataset, train_data, load=False)
        #fingerprint_unknown = get_unknown_fingerprint(cur, attributes)
        fingerprint_unknown = get_unkonwn_fp(mongo_attributes)

        counter_to_fingerprint = dict()
        for fingerprint in fingerprint_dataset:
            counter_to_fingerprint[fingerprint.getCounter()] = fingerprint

        user_id_to_counter = dict()
        for fingerprint in fingerprint_dataset:
            if fingerprint.getId() not in user_id_to_counter:
                user_id_to_counter[fingerprint.getId()] = []
            user_id_to_counter[fingerprint.getId()].append(fingerprint.getCounter())

        #print("ml_based:")
        ml_based(fingerprint_unknown, user_id_to_counter, counter_to_fingerprint, model, lambda_threshold=0.65)


if __name__ == "__main__":
    main(sys.argv[1:])
