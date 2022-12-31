import matplotlib.pyplot as plt
from sklearn import metrics
import random
import sys
import datetime
import uuid
from Levenshtein import ratio
from fingerprint_modify import Fingerprint
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.externals import joblib
import numpy as np

import string
from multiprocessing import Pool, Pipe
import time

results = []

#（不再使用）输入测试集和访问频率，生成重播序列，最后返回一个按日期排序的混合链，形如(counter,last_visit)
def generate_replay_sequence(fp_set, visit_frequency):
    """
        Takes as input a set of fingerprint fp_set,
        a frequency of visit visit_frequency in days

        Returns a list of fingerprints in the order they must be replayed
    """

    # we start by generating the sequence of replay
    # we don't store the last fp of each user since it's not realistic to replay it infinitely 不存储每一类的最后一个指纹
    user_id_to_fps = dict() #存储类别id及其对应的指纹
    for fingerprint in fp_set:
        if fingerprint.getId() not in user_id_to_fps:
            user_id_to_fps[fingerprint.getId()] = []
        user_id_to_fps[fingerprint.getId()].append(fingerprint)

    user_id_to_sequence = dict()
    for user_id in user_id_to_fps:
        # can be removed later when we don't set a limit on counter
        if len(user_id_to_fps[user_id]) > 1: #该id对应的fp数>1，去除最后一个fp？
            user_id_to_fps[user_id] = user_id_to_fps[user_id][:-1]
            sequence = []
            last_visit = user_id_to_fps[user_id][0].getStartTime()

            counter_suffix = "i"
            assigned_counter = "%d_%s" % (user_id_to_fps[user_id][0].getCounter(), counter_suffix) #getCounter()获取数据库中存储的counter
            sequence.append((assigned_counter, last_visit)) #每个类别最新fp的counter和上次收集的时间

            for fingerprint in user_id_to_fps[user_id]:
                counter_suffix = 0
                # if it is none and not the last one (last one is removed)
                #  it means the fp changed within the same time interval
                if fingerprint.getEndTime() is not None: #结束时间
                    while last_visit + datetime.timedelta(days=visit_frequency) < \
                            fingerprint.getEndTime():
                        last_visit = last_visit + datetime.timedelta(days=visit_frequency)
                        assigned_counter = "%d_%d" % (fingerprint.getCounter(), counter_suffix)
                        sequence.append((assigned_counter, last_visit))
                        counter_suffix += 1 #表示这个counter的指纹在sequence里被用作填充了几次

            user_id_to_sequence[user_id] = sequence #存每个id对应的链

    # now we generate the whole sequence
    # we start by merging all the subsequences, and then sort it by the date 合并所有id对应的链，然后按日期对其进行排序
    replay_sequence = []
    for user_id in user_id_to_sequence:
        replay_sequence += user_id_to_sequence[user_id]
    replay_sequence = sorted(replay_sequence, key=lambda x: x[1]) #按last_visit日期排序
    return replay_sequence #形成一个混合的链

#多少作测试perc_train，多少作训练
def split_data(perc_train, fingerprint_dataset):
    """
        Takes as input the percentage of fingerprints for training and
        the fingerprint dataset ordered chronologically.
        Returns the training and the test sequence
    """
    index_split = int(len(fingerprint_dataset) * perc_train)
    # train, test
    return fingerprint_dataset[: index_split], fingerprint_dataset[index_split:]


def generate_new_id():
    """
        Returns a random user id
    """
    return str(uuid.uuid4())


def candidates_have_same_id(candidate_list):
    """
        Returns True if all candidates have the same id
        Else False
    """
    if len(candidate_list) == 0:
        return False
    return not any(not x for x in [y[2] == candidate_list[0][2] for y in candidate_list])


def rule_based(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint):
    """
        Given an unknown fingerprint fingerprint_unknown,
        and a set of known fingerprints fps_available,
        tries to link fingerprint_unknown to a fingerprint in
        fps_available.
        If it can be linked it returns the id of the fingerprint it has been linked with,
        otherwise it returns a new generated user id.
    """
    forbidden_changes = [
        Fingerprint.CANVAS_JS_HASHED,
        Fingerprint.LOCAL_JS,
        Fingerprint.DNT_JS,
        Fingerprint.COOKIES_JS
    ]

    allowed_changes_with_sim = [
        Fingerprint.USER_AGENT_HTTP,
        Fingerprint.VENDOR,
        Fingerprint.RENDERER,
        Fingerprint.PLUGINS_JS,
        Fingerprint.LANGUAGE_HTTP,
        Fingerprint.ACCEPT_HTTP
    ]

    allowed_changes = [
        Fingerprint.RESOLUTION_JS,
        Fingerprint.ENCODING_HTTP,
        Fingerprint.TIMEZONE_JS
    ]
    ip_allowed = False
    candidates = list()
    exact_matching = list()
    prediction = None
    for user_id in user_id_to_fps:
        for counter_known in user_id_to_fps[user_id]:
            fingerprint_known = counter_to_fingerprint[counter_known]
            # check fingerprint full hash for exact matching 完全匹配
            if fingerprint_known.hash == fingerprint_unknown.hash:
                # either we look if there are multiple users that match
                # in that case we create new id
                # or we assign randomly?
                exact_matching.append((counter_known, None, user_id))
            elif len(exact_matching) < 1 and fingerprint_known.constant_hash == \
                    fingerprint_unknown.constant_hash:
                # we make the comparison only if same os/browser/platform
                if fingerprint_known.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] > \
                        fingerprint_unknown.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION]:
                    continue

                if fingerprint_known.hasFlashActivated() and fingerprint_unknown.hasFlashActivated() and \
                        not fingerprint_known.areFontsSubset(fingerprint_unknown):
                    continue

                forbidden_change_found = False
                for attribute in forbidden_changes:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        forbidden_change_found = True
                        break

                if forbidden_change_found: #直接进行下一次循环
                    continue

                nb_changes = 0
                changes = []
                # we allow at most 2 changes, then we check for similarity
                for attribute in allowed_changes_with_sim:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        changes.append(attribute)
                        nb_changes += 1

                    if nb_changes > 2:
                        break

                if nb_changes > 2: #直接进行下一次循环
                    continue

                sim_too_low = False
                for attribute in changes:
                    if ratio(fingerprint_known.val_attributes[attribute],
                             fingerprint_unknown.val_attributes[attribute]) < 0.75:
                        sim_too_low = True
                        break
                if sim_too_low:
                    continue

                nb_allowed_changes = 0
                for attribute in allowed_changes:
                    if fingerprint_known.val_attributes[attribute] != \
                            fingerprint_unknown.val_attributes[attribute]:
                        nb_allowed_changes += 1

                    if nb_allowed_changes > 1:
                        break

                if nb_allowed_changes > 1:
                    continue

                total_nb_changes = nb_allowed_changes + nb_changes
                if total_nb_changes == 0:
                    exact_matching.append((counter_known, None, user_id))
                else:
                    candidates.append((counter_known, total_nb_changes, user_id))
#精确匹配数>0
    if len(exact_matching) > 0:
        if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
            return exact_matching[0][2] #返回user_id
        elif ip_allowed:
            # we don't use IP address, it is just here because of a previous test!
            for elt in exact_matching:
                counter = int(elt[0])
                fingerprint_known = counter_to_fingerprint[counter_known]

                if fingerprint_known.val_attributes[Fingerprint.ADDRESS_HTTP] == \
                        fingerprint_unknown.val_attributes[Fingerprint.ADDRESS_HTTP]:
                    print("match1")
                    prediction = elt[2]
                    break
    else:
        if len(candidates) == 1 or candidates_have_same_id(candidates):
            print("match2")
            prediction = candidates[0][2]
        elif ip_allowed:
            # we don't use IP address, it is just here because of a previous test!
            for elt in candidates:
                counter = int(elt[0])
                fingerprint_known = counter_to_fingerprint[counter_known]

                if fingerprint_known.val_attributes[Fingerprint.ADDRESS_HTTP] == \
                        fingerprint_unknown.val_attributes[Fingerprint.ADDRESS_HTTP]:
                    print("match3")
                    prediction = elt[2]
                    break

    if prediction is None:
        prediction = "no match"
    print("finished match")
    return prediction


def simple_eckersley(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint):
    """
        Given an unknown fingerprint （未知指纹）fingerprint_unknown,
        and a set of known （已知指纹集合）fingerprints fps_available,
        tries to link fingerprint_unknown to a fingerprint in（判断未知指纹是否能关联在已知指纹集合中）
        fps_available.
        If it can be linked it returns the id of the fingerprint it has been linked with,
        otherwise it returns a new generated user id.
    """
    # order of attributes matter, should place most discriminative first to decrease average
    # number of comparisons
    attributes_to_test = ["fontsFlashHashed", "pluginsJSHashed", "userAgentHttp", "resolutionJS", "acceptHttp",
                          "timezoneJS", "cookiesJS", "localJS"]

    candidates = list()
    exact = False
    for user_id in user_id_to_fps:#每个设备类别id
        for counter_known in user_id_to_fps[user_id]:#各id中每个指纹counter
            attributes_different = 0
            modified_attribute = ""
            fingerprint_known = counter_to_fingerprint[counter_known]

            for attribute in attributes_to_test:
                # special case for Flash fonts
                if attribute == Fingerprint.FONTS_FLASH_HASHED:
                    # we consider that flash activation/deactivation is not a difference
                    if fingerprint_known.hasFlashActivated() and \
                            fingerprint_unknown.hasFlashActivated():
                        if fingerprint_known.val_attributes[attribute] != \
                                fingerprint_unknown.val_attributes[attribute]:
                            attributes_different += 1
                            modified_attribute = attribute
                elif fingerprint_unknown.val_attributes[attribute] != \
                        fingerprint_known.val_attributes[attribute]:
                    attributes_different += 1
                    modified_attribute = attribute

                if attributes_different > 1:
                    break

            if attributes_different == 1:
                # (counter, modified_attribute, id)
                candidates.append((counter_known, modified_attribute, user_id))
            elif attributes_different == 0:
                prediction = user_id
                exact = True

    if len(candidates) == 1 or candidates_have_same_id(candidates):
        if candidates[0][1] in ["cookiesJS", "resolutionJS", "timezoneJS", "IEDataJS",
                                "localJS", "dntJS"]:
            prediction = candidates[0][2]
        else:
            counter_to_test = int(candidates[0][0].split("_")[0])
            ratio_sim = ratio(counter_to_fingerprint[counter_to_test].val_attributes[candidates[0][1]],
                              fingerprint_unknown.val_attributes[candidates[0][1]])
            if ratio_sim > 0.85:
                prediction = candidates[0][2]
            else:
                prediction = "no match"
    elif not exact:
        prediction = "no match"

    return prediction

def generateHeader(attributes):
    header = []
    for attribute in attributes:
        if attribute == Fingerprint.ID:
            pass
        elif attribute == Fingerprint.CREATION_TIME:
            header.append(attribute)
        elif attribute == Fingerprint.ENCODING_HTTP:
            header.append(attribute)
        elif attribute == Fingerprint.TIMEZONE_JS:
            header.append(attribute)
        elif attribute == Fingerprint.PLUGINS_JS:
            header.append("simPlugs")
        elif attribute == Fingerprint.RESOLUTION_JS:
            header.append(attribute)
        elif attribute == Fingerprint.CANVAS_JS_HASHED:
            header.append(attribute)
        elif attribute == Fingerprint.FONTS_FLASH:
            header.append("hasFlash")
            header.append("sameFonts")
        else:
            header.append(attribute)

    header.append("nbChange")
    return header

# 计算指纹相似度，返回（属性相似度们，真实情况下是否属于同一id）
def compute_similarity_fingerprint(fp1, fp2, attributes, train_mode):
    similarity_vector = []
    flash_activated = fp1.hasFlashActivated() and fp2.hasFlashActivated()
    nb_changes = 0
    for attribute in attributes:
        if attribute == Fingerprint.ID:
            val_to_insert = (1 if fp1.belongToSameUser(fp2) else 0)
            similarity_vector.insert(0, val_to_insert)
        elif attribute == Fingerprint.CREATION_TIME:
            diff = fp1.getTimeDifference(fp2)
            similarity_vector.append(diff)
        # elif attribute == Fingerprint.ENCODING_HTTP:
        #     similarity_vector.append(1) if fp1.hasSameEncodingHttp(fp2) else similarity_vector.append(0)
        # elif attribute == Fingerprint.TIMEZONE_JS:
        #     similarity_vector.append(1) if fp1.hasSameTimezone(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.PLUGINS_JS:
            sim = ratio(fp1.val_attributes[attribute], fp2.val_attributes[attribute])
            similarity_vector.append(sim)
        elif attribute == Fingerprint.RESOLUTION_JS:
            similarity_vector.append(1) if fp1.hasSameResolution(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.CANVAS_JS_HASHED:
            similarity_vector.append(1) if fp1.hasSameCanvasJsHashed(fp2) else similarity_vector.append(0)
        elif attribute == Fingerprint.FONTS_FLASH:
            if flash_activated:
                similarity_vector.append(1)
                similarity_vector.append(1) if fp1.hasSameFonts(fp2) else similarity_vector.append(0)
            else:
                similarity_vector.append(0)
                similarity_vector.append(0)
        else:
            sim = ratio(str(fp1.val_attributes[attribute]), str(fp2.val_attributes[attribute]))
            similarity_vector.append(sim)
        if fp1.val_attributes[attribute] != fp2.val_attributes[attribute]:
            nb_changes += 1
            if nb_changes > 5 and not train_mode:
                return None, None

    similarity_vector.append(nb_changes)
#[0]是是否属于同一id，[1]以后是属性的相似度，返回（属性相似度们，真实情况下是否属于同一id）
    return np.asarray(similarity_vector[1:]), np.asarray(similarity_vector[0])

# 训练模型model，load=True则直接使用已有模型，model_path已有模型存储的路径
def train_ml(fingerprint_dataset, train_data, load=False, \
             model_path=sys.path[0]+"/my_0522_model_001"):
    if load:
        model = joblib.load(model_path)
    else:
        counter_to_fingerprint = dict()
        index_to_user_id = dict()
        user_ids = set()
        index = 0

        not_to_test = set([Fingerprint.PLATFORM_FLASH,
                           Fingerprint.PLATFORM_INCONSISTENCY,
                           Fingerprint.PLATFORM_JS,
                           Fingerprint.PLUGINS_JS_HASHED,
                           Fingerprint.SESSION_JS,
                           Fingerprint.IE_DATA_JS,
                           Fingerprint.ADDRESS_HTTP,
                           Fingerprint.BROWSER_FAMILY,
                           Fingerprint.COOKIES_JS,
                           Fingerprint.DNT_JS,
                           Fingerprint.END_TIME,
                           Fingerprint.FONTS_FLASH_HASHED,
                           Fingerprint.GLOBAL_BROWSER_VERSION,
                           Fingerprint.LANGUAGE_FLASH,
                           Fingerprint.LANGUAGE_INCONSISTENCY,
                           Fingerprint.LOCAL_JS,
                           Fingerprint.MINOR_BROWSER_VERSION,
                           Fingerprint.MAJOR_BROWSER_VERSION,
                           Fingerprint.NB_FONTS,
                           Fingerprint.NB_PLUGINS,
                           Fingerprint.COUNTER,
                           Fingerprint.OS,
                           Fingerprint.ACCEPT_HTTP,
                           Fingerprint.CONNECTION_HTTP,
                           Fingerprint.ENCODING_HTTP,
                           Fingerprint.RESOLUTION_FLASH,
                           Fingerprint.TIMEZONE_JS,
                           Fingerprint.VENDOR,
                           ])

        att_ml = set(fingerprint_dataset[0].val_attributes.keys())
        att_ml = sorted([x for x in att_ml if x not in not_to_test])

        for fingerprint in fingerprint_dataset:
            counter_to_fingerprint[fingerprint.getCounter()] = fingerprint
            if fingerprint.getId() not in user_ids:
                user_ids.add(fingerprint.getId())
#index_to_user_id 为了在生成负样本时随机抽取指纹
                index_to_user_id[index] = fingerprint.getId()
                index += 1

        #print("Start generating training data")
#user_id_to_fps 存放训练数据id及对应指纹
        #print(len(train_data))
        user_id_to_fps = dict()
        for fingerprint in train_data:
            if fingerprint.getId() not in user_id_to_fps:
                user_id_to_fps[fingerprint.getId()] = []
            user_id_to_fps[fingerprint.getId()].append(fingerprint)
        X, y = [], []
        attributes = sorted(fingerprint_dataset[0].val_attributes.keys())
        #正样本
        #print(len(user_id_to_fps))
        for user_id in user_id_to_fps:
            #print(len(user_id_to_fps[user_id]))
            previous_fingerprint = None
            for fingerprint in user_id_to_fps[user_id]:
                if previous_fingerprint is not None:
                    x_row, y_row = compute_similarity_fingerprint(fingerprint, previous_fingerprint, att_ml,
                                                                  train_mode=True)
                    #print(x_row)
                    X.append(x_row)
                    y.append(y_row)
                previous_fingerprint = fingerprint

        # we compute negative rows 负样本
        for user_id in user_id_to_fps:
            for fp1 in user_id_to_fps[user_id]:
                try:
                    compare_with_id = index_to_user_id[random.randint(0, len(user_id_to_fps))]
                    compare_with_fp = random.randint(0, len(user_id_to_fps[compare_with_id]))
                    fp2 = user_id_to_fps[compare_with_id][compare_with_fp]
                    x_row, y_row = compute_similarity_fingerprint(fp1, fp2, att_ml, train_mode=True)
                    X.append(x_row)
                    y.append(y_row)
                except:
                    pass

        #print("Start training model")
        model = RandomForestClassifier(n_jobs=4)
        #model = svm.SVC(C=0.55, kernel='rbf', gamma=5,probability=True)
        #model = svm.SVC(probability=True)
        #print("Training data: %d" % len(X))
        model.fit(X, y)
        #print("Model trained")
        joblib.dump(model, model_path)
        #print("model saved at: %s" % model_path)

    return model

#基于机器学习分类
def ml_based(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint, model, lambda_threshold):
    forbidden_changes = [
        Fingerprint.DNT_JS,
        Fingerprint.COOKIES_JS
    ]

    allowed_changes_with_sim = [
        Fingerprint.USER_AGENT_HTTP,
        Fingerprint.VENDOR,
        Fingerprint.RENDERER,
        Fingerprint.PLUGINS_JS,
        Fingerprint.LANGUAGE_HTTP,
        Fingerprint.ACCEPT_HTTP
    ]

    allowed_changes = [
        Fingerprint.RESOLUTION_JS,
        Fingerprint.ENCODING_HTTP,

    ]

    not_to_test = set([Fingerprint.PLATFORM_FLASH,
                       Fingerprint.PLATFORM_INCONSISTENCY,
                       Fingerprint.PLATFORM_JS,
                       Fingerprint.PLUGINS_JS_HASHED,
                       Fingerprint.SESSION_JS,
                       Fingerprint.IE_DATA_JS,
                       Fingerprint.ADDRESS_HTTP,
                       Fingerprint.BROWSER_FAMILY,
                       Fingerprint.COOKIES_JS,
                       Fingerprint.DNT_JS,
                       Fingerprint.END_TIME,
                       Fingerprint.FONTS_FLASH_HASHED,
                       Fingerprint.GLOBAL_BROWSER_VERSION,
                       Fingerprint.LANGUAGE_FLASH,
                       Fingerprint.LANGUAGE_INCONSISTENCY,
                       Fingerprint.LOCAL_JS,
                       Fingerprint.MINOR_BROWSER_VERSION,
                       Fingerprint.MAJOR_BROWSER_VERSION,
                       Fingerprint.NB_FONTS,
                       Fingerprint.NB_PLUGINS,
                       Fingerprint.COUNTER,
                       Fingerprint.OS,
                       Fingerprint.ACCEPT_HTTP,
                       Fingerprint.CONNECTION_HTTP,
                       Fingerprint.ENCODING_HTTP,
                       Fingerprint.RESOLUTION_FLASH,
                       Fingerprint.TIMEZONE_JS,
                       Fingerprint.VENDOR,
                       ])

    att_ml = set(fingerprint_unknown.val_attributes.keys())
    att_ml = sorted([x for x in att_ml if x not in not_to_test])

    ip_allowed = False
    candidates = list()
    exact_matching = list()
    prediction = None
    for user_id in user_id_to_fps:
        for counter_known in user_id_to_fps[user_id]:
            fingerprint_known = counter_to_fingerprint[counter_known]

            # check fingerprint full hash for exact matching检查精确匹配
            if fingerprint_known.hash == fingerprint_unknown.hash:
                exact_matching.append((counter_known, None, user_id))
            elif len(exact_matching) < 1 :
                #fingerprint_known.constant_hash == fingerprint_unknown.constant_hash
                # we make the comparison only if same os/browser/platform
                # if fingerprint_known.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] > \
                #         fingerprint_unknown.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION]:
                #     continue

                # forbidden_change_found = False
                # for attribute in forbidden_changes:
                #     if fingerprint_known.val_attributes[attribute] != \
                #             fingerprint_unknown.val_attributes[attribute]:
                #         forbidden_change_found = True
                #         break
                #
                # if forbidden_change_found:
                #     continue
                candidates.append((counter_known, None, user_id))
    if len(exact_matching) > 0:
        if len(exact_matching) == 1 or candidates_have_same_id(exact_matching):
            print("exactly matched:", exact_matching[0][2])
            #print(exact_matching[0][2])
            return
    elif len(candidates) > 0:
        # in this case we apply ML使用机器学习分类器
        #print("使用机器学习分类器:",len(candidates))
        data = []
        attributes = sorted(fingerprint_unknown.val_attributes.keys())
        new_candidates = []
        for elt in candidates:
            counter = int(elt[0])
            #print("counter:",counter)
            fingerprint_known = counter_to_fingerprint[counter]
#生成未知样本与candidates中候选已知指纹样本的特征向量
            x_row, _ = compute_similarity_fingerprint(fingerprint_unknown,
                                                      fingerprint_known,
                                                      att_ml, train_mode=True)
            if x_row is not None:
                data.append(x_row)
                #print("x_row is not None")
                new_candidates.append(elt)
        if len(new_candidates) > 0:
            #print(model.predict(data))
            predictions_model = model.predict_proba(data)
            #print("predict_proba=",predictions_model)
            predictions_model = 1.0 - predictions_model
            #print("predict_proba=",predictions_model)
            #选出关联度最大的3个样本？
            nearest = (-predictions_model[:, 0]).argsort()[:3]
            #print(new_candidates[nearest[0]][2])
            max_nearest = 1
            second_proba = None
            for i in range(1, len(nearest)):
                if predictions_model[nearest[i], 0] != predictions_model[nearest[0], 0]:
                    max_nearest = i
                    second_proba = predictions_model[nearest[i], 0]
                    break
            nearest = nearest[:max_nearest]
            # print('nearest:', predictions_model[nearest[0],0])
            # print('second_prob:', second_proba)

            diff_enough = True
            if second_proba is not None and predictions_model[nearest[0], 0] < second_proba + 0.1: # 0.1 = diff parameter
                diff_enough = False

            # if diff_enough and predictions_model[nearest[0], 0] > lambda_threshold and candidates_have_same_id(
            #         [candidates[x] for x in nearest]):
            if diff_enough and predictions_model[nearest[0], 0] > lambda_threshold :
                #找到最相似的样本
                prediction = new_candidates[nearest[0]][2]
                print("ml nearest:",prediction)
    if prediction is None:
        prediction = "no match"
        print(prediction)


def load_scenario_result(filename):
    """
        Loads and returns a scenario result from disk
    """
    scenario_result = []
    with open(filename, "r") as f:
        for line in f:
            l_split = line.split(",")
            scenario_result.append((l_split[0], l_split[1]))

    return scenario_result


def compute_ownership(fingerprints):
    real_user_id_to_count = dict()
    for fingerprint in fingerprints:
        if fingerprint.getId() in real_user_id_to_count:
            real_user_id_to_count[fingerprint.getId()] += 1
        else:
            real_user_id_to_count[fingerprint.getId()] = 1

    max_key = max(real_user_id_to_count, key=real_user_id_to_count.get)
    return float(real_user_id_to_count[max_key] / len(fingerprints)), max_key

#（不再使用）
def find_longest_chain(real_user_id, real_id_to_assigned_ids, assigned_ids_to_fingerprint):
    """
        找真实id被重新分配后形成的最长链
    """
    assigned_ids = real_id_to_assigned_ids[real_user_id]
    assigned_id_to_count = dict()
    for assigned_id in assigned_ids:
        tmp_count = 0
        for fingerprint in assigned_ids_to_fingerprint[assigned_id]:
            if fingerprint.getId() == real_user_id:
                tmp_count += 1

        assigned_id_to_count[assigned_id] = tmp_count

    return max(assigned_id_to_count.items(), key=lambda x: x[1])[1]


#将混合链的id分配结果写入文件中
def analyse_scenario_result(scenario_result, fingerprint_dataset,
                            fileres1="./results/res1.csv",
                            fileres2="./results/res2.csv"):
    """
        Performs an analysis of a scenario result 分析结果存入.csv结果文件
    """
    counter_to_fingerprint = dict()
    real_user_id_tp_nb_fps = dict()
	#真实id
    real_ids = set()
	#真实id有几个指纹样本
    aareal_user_id_to_fps = dict()
    for fingerprint in fingerprint_dataset:
        counter_to_fingerprint[fingerprint.getCounter()] = fingerprint
        real_ids.add(fingerprint.getId())
        if fingerprint.getId() not in aareal_user_id_to_fps:
            aareal_user_id_to_fps[fingerprint.getId()] = 1
        else:
            aareal_user_id_to_fps[fingerprint.getId()] += 1

    # we map new assigned ids to real ids in database
	#分配的新id
    assigned_ids = set()
	#以数据库counter为索引，存被分配的新id
    real_id_to_assigned_ids = dict()
    assigned_id_to_real_ids = dict()
    assigned_id_to_fingerprints = dict()
    for elt in scenario_result:
        counter = int(elt[0].split("_")[0])
        assigned_id = elt[1]
        assigned_ids.add(assigned_id)
		#重新分配id后，指纹的原真实id
        real_db_id = counter_to_fingerprint[counter].getId()
		#real_user_id_tp_nb_fps真实id在形成的混合链接中，具有的指纹数量
        if real_db_id not in real_user_id_tp_nb_fps:
            real_user_id_tp_nb_fps[real_db_id] = 1
        else:
            real_user_id_tp_nb_fps[real_db_id] += 1
        #real_id_to_assigned_ids：真实id被重分配的id数量
        if real_db_id not in real_id_to_assigned_ids:
            real_id_to_assigned_ids[real_db_id] = set()
        real_id_to_assigned_ids[real_db_id].add(assigned_id)

        if assigned_id not in assigned_id_to_real_ids:
            assigned_id_to_real_ids[assigned_id] = set()
            assigned_id_to_fingerprints[assigned_id] = []

        assigned_id_to_real_ids[assigned_id].add(counter_to_fingerprint[counter].getId())
        assigned_id_to_fingerprints[assigned_id].append(counter_to_fingerprint[counter])

    with open(fileres1, "w") as f:
        f.write("%s,%s,%s,%s,%s\n" % ("real_id", "nb_assigned_ids", "nb_original_fp", "ratio", "max_chain"))
        # don't iterate over reals_ids since some fps don't have end date and are not present
        for real_id in real_id_to_assigned_ids:
            max_chain = find_longest_chain(real_id, real_id_to_assigned_ids, assigned_id_to_fingerprints)
            #ratio：指纹数量 / 被分配的ip数量
            ratio_stats = real_user_id_tp_nb_fps[real_id] / len(real_id_to_assigned_ids[real_id])
            f.write("%s,%d,%d,%f,%d\n" % (real_id,
                                          len(real_id_to_assigned_ids[real_id]),
                                          real_user_id_tp_nb_fps[real_id],
                                          ratio_stats, max_chain)
                    )

    with open(fileres2, "w") as f:
        f.write("%s,%s,%s,%s,%s\n" % ("assigned_id", "nb_assigned_ids", "nb_fingerprints",
                                      "ownership", "id_ownership"))
        for assigned_id in assigned_id_to_real_ids:
            ownership, ownsership_id = compute_ownership(assigned_id_to_fingerprints[assigned_id])
            f.write("%s,%d,%d,%f,%s\n" % (assigned_id, len(assigned_id_to_real_ids[assigned_id]),
                                          len(assigned_id_to_fingerprints[assigned_id]), ownership,
                                          ownsership_id))


def compute_distance_top_left(tpr, fp):
    return (0 - fp) * (0 - fp) + (1 - tpr) * (1 - tpr)

def collect_results(result):
    results.extend(result)


def simple_catch(fn, max_diff, nb_cmp_per_id, conn, attributes):
    try:
        fn(max_diff, nb_cmp_per_id, conn, attributes)
    except Exception as e:
        print(e)





