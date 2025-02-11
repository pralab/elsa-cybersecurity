import random
from deap import base, creator, tools
import logging
from copy import deepcopy
import numpy as np
import scipy as sp
from sklearn.feature_extraction.text import CountVectorizer


class Feature:
    def __init__(self, add, remove):
        self.add = add
        self.remove = remove


DREBIN_FEATURES = {
    "req_permissions": Feature(True, False),
    "activities": Feature(True, True),
    "services": Feature(True, True),
    "providers": Feature(True, True),
    "receivers": Feature(True, True),
    "features": Feature(True, False),
    "intent_filters": Feature(True, False),
    "used_permissions": Feature(True, False),
    "api_calls": Feature(True, True),
    "suspicious_calls": Feature(True, True),
    "urls": Feature(True, True)
}


class FeatureSpaceAttack:
    """
    Genetic black-box feature-space attack that manipulates the features of
    malware samples to evade the classifier.
    The attack need a set of goodware samples from which to initialize the
    population.
    The optimization is performed on individuals which consists of manipulation
    vectors, that contain the indexes of the features that can be manipulated.
    If a feature can be added, the index will have positive sign, whereas
    if it can be removed the index will be negative.
    """

    def __init__(self, classifier, logging_level=logging.INFO):
        """

        Parameters
        ----------
        classifier : BaseModel
            The trained classifier to attack.
        logging_level : int
            Set the verbosity of the logger.
        """

        self.clf = classifier
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)

        # Private attributes
        self._pop = None
        self._toolbox = None
        self._n_iterations = None
        self._n_features = None
        self._n_candidates = None
        self._stagnation = None

    def run(self, malware_features, goodware_features, n_iterations=100,
            n_features=5, n_candidates=5, stagnation=5, seed=0):
        """Runs the attack.

        Parameters
        ----------
        malware_features : iterable of iterables of strings
            Iterable of shape (n_samples, n_features) containing textual
            features of malware samples to attack in the format
            <feature_type>::<feature_name>.
        goodware_features : iterable of iterables of strings
            Iterable of shape (n_samples, n_features) containing textual
            features of goodware samples to be used for the attack
            initialization in the format <feature_type>::<feature_name>.
        n_iterations : int
            Max number of iterations for the genetic attack.
        n_features : int
            Number of features to be added during the attack.
        n_candidates : int
            Number of considered goodware samples to initialize the population.
        stagnation : int
        seed : int

        Returns
        -------
        list of strings
            The features of manipulated malware samples after the attack.
        """
        self._n_iterations = n_iterations
        self._n_features = n_features
        self._n_candidates = n_candidates
        self._stagnation = stagnation

        random.seed(seed)
        np.random.seed(seed)

        self._pop, self._toolbox = self._init_attack(goodware_features)

        adv_examples = []
        for i, sample in enumerate(malware_features):
            self.logger.info(f"Attacking sample {i}")
            adv_examples.append(self._run(sample))
        return adv_examples

    def _run(self, malware_features):
        """Runs the attack on a single sample.
        """
        label, score = self.clf.predict([malware_features])
        if label == 0:
            self.logger.debug("Skipping sample, it is not detected as malware")
            return malware_features
        self.logger.debug(f"Initial confidence: {score.item()}")

        # filter out features that are not used by the classifier
        unused_features = [feat for feat in malware_features
                           if feat not in self.clf.input_features]
        malware_features = [feat for feat in malware_features
                            if feat not in unused_features]

        x_orig = self._get_features_idxs(malware_features)
        pop = deepcopy(self._pop)

        manipulation_space = self._build_manipulation_space(malware_features)

        # Evaluate the entire population
        for ind in pop:
            ind.label, ind.fitness.values = self.fitness(x_orig, ind)

        # CXPB is the probability with which two individuals are crossed
        # MUTPB is the probability for mutating an individual
        CXPB, MUTPB = 0.9, 0.4

        # Variable keeping track of the number of generations
        g = 0

        last_n_best_fits = []
        target_adv = malware_features

        # Begin the evolution
        while g < self._n_iterations:
            # Select the next generation individuals
            offspring = self._toolbox.select(pop, self._n_candidates)
            # Clone the selected individuals
            offspring = list(map(self._toolbox.clone, offspring))

            # Apply crossover and mutation on the offspring
            for child1, child2 in zip(offspring[::2], offspring[1::2]):
                # Cross two individuals with probability CXPB
                if random.random() < CXPB:
                    self._toolbox.mate(child1, child2)
                    # Fitness values of the children must be recalculated later
                    del child1.fitness.values
                    del child2.fitness.values

            for mutant in offspring:
                # Mutate an individual with probability MUTPB
                if random.random() < MUTPB:
                    self._toolbox.mutate(mutant, manipulation_space)
                    del mutant.fitness.values

            # Evaluate the individuals with an invalid fitness
            invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
            for ind in invalid_ind:
                ind.label, ind.fitness.values = self.fitness(x_orig, ind)
            pop.extend(invalid_ind)

            fits = np.array([ind.fitness.values[0] for ind in pop])
            best_idx = np.argmin(fits)
            best_fitness = fits[best_idx]
            last_n_best_fits.append(best_fitness)
            last_n_best_fits = last_n_best_fits[-self._stagnation:]

            # Update adv sample in the first iteration and if fitness
            # is improved
            if g == 0 or (len(last_n_best_fits) > 1 and
                          best_fitness != last_n_best_fits[-2]):
                target_adv = self._apply_manipulations(x_orig, pop[best_idx])
                label = pop[best_idx].label
                self.logger.debug(
                    f"Generation {g + 1} - score {best_fitness}")
                # early stop
                if label == 0:
                    return target_adv + unused_features
            g += 1

        return target_adv + unused_features

    def _build_manipulation_space(self, malware_features):
        """
        Collects the indexes of the features that can be manipulated.
        If a feature can be added, the index will have positive sign, whereas
        if it can be removed the index will be negative.
        NB: to use this format we need to add 1 to each index, otherwise we
        will lose the addition/removal information for index 0.

        Parameters
        ----------
        malware_features : list of str
            Textual features of the malware sample.
        Returns
        -------
        set
            The feasible manipulations.
        """
        self.logger.debug(f"Building manipulation space")
        manipulation_space = set()
        for feature in malware_features:
            # malware has feature and removal is feasible
            if DREBIN_FEATURES[feature.split("::")[0]].remove:
                manipulation_space.add(
                    -(self.clf.input_features.index(feature)+1))
        candidate_features = np.unique(np.array(self._pop))
        for i in candidate_features:
            if DREBIN_FEATURES[
              self.clf.input_features[i-1].split("::")[0]].add:
                manipulation_space.add(i)
        return manipulation_space

    def _init_attack(self, goodware_features):
        """Prepares the population and the functions used by the
        genetic attack.
        """

        # get the initial manipulation vectors from the selected candidates
        candidates = self._generate_candidates(goodware_features)

        def init_individual(icls, content):
            return icls(content)

        def init_population(pcls, ind_init):
            """Initializes the manipulation vectors from candidate's features
            and adds them to the population"""
            return pcls(ind_init(
                np.random.choice(c.nonzero()[1]+1, self._n_features))
                        for c in candidates)

        creator.create("FitnessMin", base.Fitness, weights=(-1.0,))
        creator.create("Individual", np.ndarray,
                       fitness=creator.FitnessMin, label=int)

        toolbox = base.Toolbox()
        # Register the function to initialize individuals and population
        toolbox.register("individual_guess", init_individual,
                         creator.Individual)
        toolbox.register("population_guess", init_population, list,
                         toolbox.individual_guess)
        pop = toolbox.population_guess()  # Initialize population

        # Register the crossover operator
        toolbox.register("mate", self.crossover)
        # Register a mutation operator with a probability to
        # flip each attribute/gene of 0.3
        toolbox.register("mutate", self.random_mutation, indpb=0.3)
        # Operator for selecting individuals for breeding the next
        # generation: each individual of the current generation
        # is replaced by the 'fittest' (best) of the selected candidates
        # from the current generation.
        toolbox.register("select", tools.selTournament,
                         tournsize=self._n_candidates)

        return pop, toolbox

    def _generate_candidates(self, goodware_features):
        # Select candidates that have at least `n_features` used features by
        # the classifier
        self.logger.debug("Generating candidates")
        vectorizer = CountVectorizer(
            input="content", lowercase=False, tokenizer=lambda x: x,
            token_pattern=None, binary=True)
        vectorizer.vocabulary_ = {feat: idx for idx, feat in
                                  enumerate(self.clf.input_features)}
        vectorizer.fixed_vocabulary_ = False
        vectorizer.stop_words_ = set()

        candidates = vectorizer.transform(goodware_features)
        mask = candidates.sum(axis=1).A1 > self._n_features
        n_valid = mask.sum()
        if n_valid > self._n_candidates:
            valid_indices = np.where(mask)[0]
            mask[np.random.choice(valid_indices, replace=False,
                                  size=n_valid - self._n_candidates)] = False
        candidates = candidates[mask, :]

        # if not enough candidates are found, generate random samples
        # (it should be avoided)
        if candidates.shape[0] < self._n_candidates:
            n = self._n_candidates - candidates.shape[0]
            data = np.ones(self._n_features * n, dtype=int)
            indices = np.hstack(
                [np.random.choice(candidates.shape[1], size=self._n_features,
                                  replace=False) for _ in range(n)])
            indptr = np.arange(0, n * self._n_features + 1, self._n_features)
            rnd_rows = sp.sparse.csr_matrix((data, indices, indptr),
                                            shape=(n, candidates.shape[1]))
            candidates = sp.sparse.vstack((candidates, rnd_rows))

        return candidates

    def fitness(self, x_orig, delta):
        """Calculates the fitness of an individual.

        Parameters
        ----------
        x_orig: set
            Feature indexes of the original malware sample.
        delta : np.ndarray
            Array containing the manipulations to be applied to the malware sample.

        Returns
        -------
        float :
            The fitness
        """
        x_adv = self._apply_manipulations(x_orig, delta)
        labels, scores = self.clf.predict([x_adv])
        return labels.item(), (scores.item(),)

    def _apply_manipulations(self, x_orig, delta):
        """
        Apply the manipulations encoded in delta to the provided malware
        sample.

        Parameters
        ----------
        x_orig: set
            Feature indexes of the original malware sample.
        delta : np.ndarray
            Array containing the manipulations to be applied to the malware
            sample.

        Returns
        -------
        list of str:
            The textual features of the manipulated sample
        """
        add = set()
        remove = set()
        for idx in delta:
            if idx > 0 and (idx-1) not in x_orig:
                add.add(idx-1)
            elif idx < 0 and abs(idx)-1 in x_orig:
                remove.add(abs(idx)-1)

        return self._get_textual_features(x_orig.union(add).difference(remove))

    def crossover(self, ind1, ind2):
        """
        Executes a crossover between the manipulations contained in the two
        individuals, swapping a randomly selected set of manipulations from
        the manipulation space.

        Parameters
        ----------
        ind1 : np.ndarray
            The first manipulation vector participating in the crossover.
        ind2 : np.ndarray
            The second manipulation vector participating in the crossover.

        Returns
        -------
        np.ndarray
            The new manipulation vector.
        """
        min_l = min(len(ind1), len(ind2))
        swap_idx = random.sample(range(min_l), k=random.randint(1, min_l))
        # this works as numpy advanced indexing always return a copy
        ind1[swap_idx], ind2[swap_idx] = ind2[swap_idx], ind1[swap_idx]
        return ind1, ind2

    def random_mutation(self, individual, manipulation_space, indpb):
        """
        Insert mutations in the manipulation vector with a given probability
        for each feature included in the manipulation space.
        The mutation are applied in-place.

        Parameters
        ----------
        individual : np.ndarray
            The manipulation vector.
        manipulation_space : set
            Set containing the feasible manipulations.
        indpb : float
            Independent probability for each feature to be mutated.

        Returns
        -------
        np.ndarray
            The new manipulation vector.
        """
        for idx in range(individual.shape[0]):
            if random.random() < indpb:
                manipulation = random.choice(tuple(manipulation_space))
                if manipulation not in individual:
                    individual[idx] = manipulation
        return individual,

    def _get_features_idxs(self, features):
        """
        Converts textual features into a set of indexes.

        Parameters
        ----------
        features : list of str
            List containing the textual features.
        Returns
        -------
        set
            The indexes of the features corresponding to the textual features.
        """
        return set(self.clf.input_features.index(f) for f in features)

    def _get_textual_features(self, x):
        """
        Given an array of feature indexes, returns the list of the
        corresponding textual features.

        Parameters
        ----------
        x : set
            The feature indexes.

        Returns
        -------
        list of string
            The textual features corresponding to the input vector.
        """
        return [self.clf.input_features[i] for i in x]
