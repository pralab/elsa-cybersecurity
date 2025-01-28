import random
from deap import base, creator, tools
import logging
from secml.parallel import parfor2
import numpy as np
from .manipulation import Manipulator, ManipulationSpace, Manipulations
from .feature_extraction import FeatureExtractor
import os
import tempfile


def _apply_manipulations(i, manipulator, pop, manipulation_space):
    manipulations = manipulation_space.get_manipulations_from_vector(pop[i])
    pop[i].apk_path = manipulator.manipulate(manipulations, i)
    return pop[i]


class ProblemSpaceAttack:
    def __init__(self, classifier, manipulated_apks_dir,
                 logging_level=logging.INFO, features_dir=None):
        """
        Genetic black-box problem-space attack that manipulates the APK files
        of malware samples to evade the classifier.
        The attack need a set of goodware samples from which to initialize the
        population.
        The optimization is performed on individuals which consists of
        manipulation vectors, that contain the indexes of the features that can
        be manipulated (injected or obfuscated).

        Parameters
        ----------
        classifier : BaseModel
            The trained classifier to attack.
        manipulated_apks_dir : str
            The directory where the adversarial APKs will be stored.
        logging_level : int
            Set the verbosity of the logger.
        features_dir : string or None
            If provided, the extracted features will be stored in this path and
            retrieved from it if available.
        """

        self.clf = classifier
        self.manipulated_apks_dir = manipulated_apks_dir
        if not os.path.exists(manipulated_apks_dir):
            os.makedirs(manipulated_apks_dir)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging_level)

        # Private attributes
        self._feature_extractor = FeatureExtractor(
            logging_level=logging.ERROR)
        self._features_cache = features_dir
        self._candidate_features = None
        self._n_iterations = None
        self._n_features = None
        self._n_candidates = None
        self._stagnation = None
        self._n_jobs = None

    def run(self, malware_samples, goodware_samples, n_iterations=100,
            n_features=5, n_candidates=5, stagnation=5, seed=0, n_jobs=1):
        """Runs the attack.

        Parameters
        ----------
        malware_samples : list of strings
            List with the absolute path of each malware APK file to attack.
        goodware_samples : list of strings
            List with the absolute path of each goodware APK file to be used
            for the attack initialization.
        n_iterations : int
            Max number of iterations for the genetic attack.
        n_features : int
            Number of features to be added during the attack.
        n_candidates : int
            Number of considered goodware samples to initialize the population.
        stagnation : int
        seed : int
        n_jobs : int

        Returns
        -------
        list of tuples (int, float, str)
            For each malware sample, a tuple is returned containing the
            predicted label and score after the attack and the path of the
            manipulated APK file. If a sample is already undetected, the tuple
            will contain the predicted label and score and the path of the
            original sample.
        """
        self._n_iterations = n_iterations
        self._n_features = n_features
        self._n_candidates = n_candidates
        self._stagnation = stagnation
        self._n_jobs = n_jobs

        random.seed(seed)
        np.random.seed(seed)

        # get the features from the selected candidates
        self._generate_candidate_features(goodware_samples)

        results = []
        for i, sample in enumerate(malware_samples):
            self.logger.info(f"Attacking sample {i}")
            results.append(self._run(sample))
        return results

    def _run(self, malware_sample):
        """Runs the attack on a single sample.
        """
        label, score = self.clf.classify([malware_sample])
        label, score = label.item(), score.item()
        if label == 0:
            self.logger.debug("Skipping sample, it is not detected as malware")
            return label, score, malware_sample
        self.logger.debug(f"Initial confidence: {score}")

        adv_apk_path = malware_sample
        manipulator = None
        pop = None
        best_fitness = score

        try:
            manipulator = Manipulator(malware_sample,
                                      self.manipulated_apks_dir)
            pop, toolbox, manipulation_space = \
                self._init_attack(malware_sample, manipulator)

            # Evaluate the entire population
            pop = self.fitness(manipulator, pop, manipulation_space)

            if not pop:
                self.logger.debug("Trying to reinitialize the attack")
                pop, toolbox, manipulation_space = \
                    self._init_attack(malware_sample, manipulator)
                pop = self.fitness(manipulator, pop, manipulation_space)
                if not pop:
                    raise Exception("No manipulation can be applied "
                                    "to this APK")

            # CXPB is the probability with which two individuals are crossed
            # MUTPB is the probability for mutating an individual
            CXPB, MUTPB = 0.9, 0.4

            # Variable keeping track of the number of generations
            g = 0

            last_n_best_fits = []

            # Begin the evolution
            while g < self._n_iterations:
                # Select the next generation individuals
                offspring = toolbox.select(pop, self._n_candidates)
                # Clone the selected individuals
                offspring = list(map(toolbox.clone, offspring))

                # Apply crossover and mutation on the offspring
                for child1, child2 in zip(offspring[::2], offspring[1::2]):
                    # Cross two individuals with probability CXPB
                    if random.random() < CXPB:
                        toolbox.mate(child1, child2)
                        # Fitness values of the children must be recalculated later
                        del child1.fitness.values
                        del child2.fitness.values

                for mutant in offspring:
                    # Mutate an individual with probability MUTPB
                    if random.random() < MUTPB:
                        toolbox.mutate(mutant, manipulation_space)
                        del mutant.fitness.values

                # Evaluate the individuals with an invalid fitness
                invalid_ind = [ind for ind in offspring if
                               not ind.fitness.valid]
                invalid_ind = self.fitness(
                    manipulator, invalid_ind, manipulation_space)
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
                    label = pop[best_idx].label
                    score = pop[best_idx].score
                    adv_apk_path = pop[best_idx].apk_path
                    self.logger.debug(
                        f"Generation {g + 1} - score {best_fitness}")
                    # early stop
                    if label == 0:
                        self.logger.info(f"Attack finished - "
                                         f"score {best_fitness}")
                        return
                else:
                    self.logger.debug(f"Generation {g + 1} - no improvements")
                g += 1

            self.logger.info(f"Attack finished - " f"score {best_fitness}")
        except Exception as e:
            self.logger.error(f"Error with sample {malware_sample}: {str(e)}")
        finally:
            if manipulator:
                manipulator.clean_data()
            for tmp_f in os.listdir(tempfile.gettempdir()):
                if tmp_f.startswith("APKTOOL") or tmp_f.endswith(".apk"):
                    try:
                        os.remove(os.path.join(tempfile.gettempdir(), tmp_f))
                    except FileNotFoundError:
                        pass
            if pop:
                for ind in pop:
                    if ind.apk_path == adv_apk_path:
                        adv_apk_path = os.path.join(
                            os.path.dirname(ind.apk_path), "adv_" +
                            os.path.basename(malware_sample))
                        os.rename(ind.apk_path, adv_apk_path)
                    elif os.path.exists(ind.apk_path):
                        os.remove(ind.apk_path)
            return label, score, adv_apk_path

    def _init_attack(self, malware_sample, manipulator):
        """Prepares the population, the manipulation space and the functions
        used by the genetic attack.
        """
        malware_features = self._feature_extractor.extract_features(
            [malware_sample], out_dir=self._features_cache)
        manipulation_space = self._build_manipulation_space(
            malware_features[0], manipulator)
        if not manipulation_space:
            raise Exception("No manipulation can be applied.")

        def init_individual(icls, content):
            return icls(content)

        def init_population(pcls, ind_init):
            """Initializes the manipulation vectors from the manipulation space
            and adds them to the population"""
            return pcls(ind_init(
                self._get_random_manipulation_vector(manipulation_space))
                        for _ in range(self._n_candidates))

        creator.create("FitnessMin", base.Fitness, weights=(-1.0,))
        creator.create("Individual", np.ndarray,
                       fitness=creator.FitnessMin, apk_path=str, score=float,
                       label=int)

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

        return pop, toolbox, manipulation_space

    def _generate_candidate_features(self, goodware_samples):
        # Extract the features from the provided goodware samples, select only
        # features that can be manipulated (added)
        self._candidate_features = []
        self.logger.debug("Generating candidates")
        goodware_features = self._feature_extractor.extract_features(
            goodware_samples, out_dir=self._features_cache)
        self._candidate_features = ManipulationSpace.get_valid_injections(
            goodware_features)

    def _build_manipulation_space(self, malware_features, manipulator):
        """
        Create the manipulation space, containing the features that can be
        manipulated (injected or obfuscated).

        Parameters
        ----------
        malware_features : list of str
            Textual features of the malware sample.
        manipulator : Manipulator
            Manipulator object
        Returns
        -------
        ManipulationSpace
            Object containing the features that can be manipulated.
        """
        self.logger.debug(f"Building manipulation space")
        manipulation_space = ManipulationSpace(self._candidate_features,
                                               malware_features)
        error_free_injections = manipulator.get_error_free_manipulations(
            manipulation_space.get_all_injections(), self._n_jobs)
        error_free_obfuscations = manipulator.get_error_free_manipulations(
            manipulation_space.get_all_obfuscations(), self._n_jobs)
        error_free_manipulations = Manipulations(
            error_free_injections.inject, error_free_obfuscations.obfuscate)
        manipulation_space.set_error_free_manipulations(
            error_free_manipulations)
        return manipulation_space

    def _get_random_manipulation_vector(self, manipulation_space):
        """
        Generates a random manipulation vector, that contains the indexes of
        the features in the manipulation space that can be modified.

        Parameters
        ----------
        manipulation_space: ManipulationSpace
            Object containing the features that can be manipulated.

        Returns
        -------
        np.ndarray
            The manipulation vector.
        """
        return np.random.choice(
            np.arange(len(manipulation_space)), replace=False,
            size=min(len(manipulation_space), self._n_features))

    def fitness(self, manipulator, pop, manipulation_space):
        """Calculates the fitness of a list of individuals.

        Parameters
        ----------
        manipulator : Manipulator
            Manipulator object.
        pop : list of np.ndarray
            List of arrays containing the individuals (i.e., the manipulations
            to be applied to the malware sample).
        manipulation_space : ManipulationSpace
            Object containing the features that can be manipulated.

        Returns
        -------
        list of np.ndarray
            The individual list updated with fitness and manipulated apk paths.
        """
        self.logger.debug(f"Applying manipulations to {len(pop)} samples")
        updated_pop = [ind for ind in parfor2(
            _apply_manipulations, len(pop), self._n_jobs, manipulator, pop,
            manipulation_space) if ind.apk_path is not None and
            os.path.isfile(ind.apk_path)]
        if not updated_pop:
            self.logger.debug(f"All the manipulations failed")
        else:
            self.logger.debug(f"Computing fitness for "
                              f"{len(updated_pop)} samples")
            labels, scores = self.clf.classify(
                [ind.apk_path for ind in updated_pop])
            for i, ind in enumerate(updated_pop):
                ind.fitness.values = (scores[i],)
                ind.score = scores[i]
                ind.label = labels[i]
        return updated_pop

    def crossover(self, ind1, ind2):
        """
        Executes a crossover between the manipulations contained in the two
        individuals, swapping a randomly selected set of manipulations.

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
        manipulation_space_idx : set
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
                manipulation = random.randrange(0, len(manipulation_space))
                if manipulation not in individual:
                    individual[idx] = manipulation
        return individual,
