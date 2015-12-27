(ns seweg.protocols.snmp.oid-repository
  (:require [clojure.set :refer (map-invert)]))



(defn split-oid
  "Function takes OID value as vector and returns
  vector of known OID, as keyword and rest of oid value.
  Function also alows to specify known nuber of OID digits.

  Known OID keys are defined in repository."
  ([oid-key] (split-oid oid-key 0))
  ([oid-key n]
   (loop [ko (vec (take n oid-key))
          vo (drop n oid-key)]
     (if-not (contains? *repository* (conj ko (first vo)))
       [ko vo]
       (recur (conj ko (first vo)) (rest vo))))))

(defn find-oid
  "Returns OID value. If input argument is a keyword, than
  OID vector is returned and vice versa."
  [oid-key]
  (cond
    (keyword? oid-key) (get *repository-inv* oid-key)
    (vector? oid-key) (get *repository* oid-key)
    :else (assert false "Inappropriate input value. Allowed types are keyword and vector")))

 (defn normalize-oid
  "Function allways returns input OID value as vector."
   [oid]
   (if-not (vector? oid) (find-oid oid) oid))

(defn is-child-of-oid?
  "Test function that examines if OID is child of parent.
  Input values can be keywords or vectors and combination."
  [oid parent]
  (let  [o  (if  (vector? oid) oid (find-oid oid))
         p (if  (vector? parent) parent (find-oid parent))]
    (if (> (count p) (count o))
      false
      (= (take (count p) o) p))))

(defn find-children
  "Function returns children of OID if it is contained
  in repository. As second argument it is possible to
  specify output result as sorted or not."
  ([oid-key] (find-children oid-key false))
  ([oid-key ^Boolean sort-children?] (let [o (if (vector? oid-key) oid-key (find-oid oid-key))
                                           r (remove #(= o %) (filter #(= (take (count o) %) o) (keys *repository*)))]
                                      (when r (if sort-children? (sort r) r)))))

(defn has-children? [oid]
  "Function checks if OID has children or not lazily."
  (boolean (some seq (find-children oid))))

(defn list-oid
  "Function lists known OID children for easier development."
  [oid-key & opts]
  (if-let [c (find-children oid-key)]
    (doseq [x (map #(hash-map (vec %) (get *repository* %)) c)] (println x))))

(defn oid2str [oid-key]
  (apply str (interpose "." oid-key)))
