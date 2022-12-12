#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define K_VALUE 3
#define N_VALUE 30
#define L_VALUE 4

typedef struct {
	int K, L, N;
	int tau;
	int *sigma;
	int **weights;
} Machine;

void InitMachine(Machine *m) {
	int **mat = (int**) malloc(m->K * sizeof(int*));

	for (int i = 0; i < m->K; i++)
		mat[i] = (int*) malloc(m->N * sizeof(int));

	m->weights = mat;

	for (int i = 0; i < m->K; i++) {
		for (int j = 0; j < m->N; j++) {
			mat[i][j] = (rand() % (m->L + m->L)) - m->L;
		}
	}

	m->sigma = (int*) malloc(m->K * sizeof(int));
}

enum UpdateRules {
	HEBBIAN, ANTI_HEBBIAN, RANDOM_WALK
};

int Theta(int t1, int t2) {
	if (t1 == t2)
		return 1;
	else
		return 0;
}

void Update(Machine *m, int** lastInput, int tau2, enum UpdateRules rule) {
	if (m->tau == tau2) {
		//printf("\n*** updating!***\n");

		switch (rule) {
			case HEBBIAN:
				Hebbian(m, lastInput, m->sigma, m->tau, tau2);
				break;
			/*case ANTI_HEBBIAN:
			 AntiHebbian(this, lastInput, sigma, tau, tau2);
			 break;
			 case RANDOM_WALK:
			 RandomWalk(this, lastInput, sigma, tau, tau2);
			 break;*/
		}
	}
}

int clip(int input, int max, int min)
{
  if(input > max)
    return max;
  if(input < min)
    return min;

  return input;
}

void Hebbian(Machine *m, int **input, int *sigma, int tau1, int tau2) {
	int tempValue;
	//print("before: ${m.wList}");

	for (int i = 0; i < m->K; i++) {
		for (int j = 0; j < m->N; j++) {
			tempValue = input[i][j] * tau1 * Theta(sigma[i], tau1) * Theta(tau1, tau2);
			m->weights[i][j] += tempValue;
			m->weights[i][j] = clip(m->weights[i][j], m->L, -m->L);
		}
	}
}

void PrintWeights(Machine *m) {
	printf("\nWeights of machine...\n");
	for (int i = 0; i < m->K; i++) {
		for (int j = 0; j < m->N; j++) {
			printf(" %d ", m->weights[i][j]);
		}

		printf("\n");
	}
}

int funSgn(int input) {
	if (input < 0) {
		return -1;
	} else if (input == 0) {
		return 0;
	} else if (input > 0) {
		return 1;
	}

	return -1;
}

int GetOutput(Machine *m, int **input) {
	int ttau = 1;

	for (int k = 0; k < m->K; k++) {
		int sum = 0;

		for (int n = 0; n < m->N; n++) {
			sum += input[k][n] * m->weights[k][n];
		}

		sum = funSgn(sum);
		m->sigma[k] = sum;

		ttau *= sum;
	}

	m->tau = ttau;

	return ttau;
}

void GenerateRandomInputs(int** input)
{
	for(int i = 0; i < K_VALUE; i++)
	{
		for(int j = 0; j < N_VALUE; j++)
		{
			input[i][j] = (rand() % (L_VALUE + L_VALUE)) - L_VALUE;
		}
	}
}

void PrintInputs(int** m) {
	printf("\nCommon random inputs...\n");
	for (int i = 0; i < K_VALUE; i++) {
		for (int j = 0; j < N_VALUE; j++) {
			printf(" %d ", m[i][j]);
		}

		printf("\n");
	}
}

int CheckWeighs(Machine *m1, Machine *m2) {
	for (int i = 0; i < m1->K; i++) {
		for (int j = 0; j < m1->N; j++) {
			if(m1->weights[i][j] != m2->weights[i][j])
				return -1;
		}
	}

	return 1;
}

int main() {
	// Initialization, should only be called once.
	srand(time(NULL));

	printf("\PIETRODIG's machines...");
	Machine m1, m2;

	m1.K = K_VALUE;
	m1.N = N_VALUE;
	m1.L = L_VALUE;

	m2.K = K_VALUE;
	m2.N = N_VALUE;
	m2.L = L_VALUE;

	InitMachine(&m1);
	InitMachine(&m2);

	//PrintWeights(&m1);
	//PrintWeights(&m2);

	int** common_inputs = (int**) malloc(K_VALUE * sizeof(int*));
	for (int i = 0; i < K_VALUE; i++)
		common_inputs[i] = (int*) malloc(N_VALUE * sizeof(int));

	//GenerateRandomInputs(common_inputs);
	//PrintInputs(common_inputs);

	int out1, out2, res;

	//out1 = GetOutput(&m1, common_inputs);
	//out2 = GetOutput(&m2, common_inputs);

	//printf("*** OUTPUTS *** \n%d \n%d", out1, out2);

	int synch = -1, h = 0;

	while(synch == -1)
	{
		//printf("\nh == %d\n", h);

		GenerateRandomInputs(common_inputs);
		//PrintInputs(common_inputs);

		out1 = GetOutput(&m1, common_inputs);
		out2 = GetOutput(&m2, common_inputs);

		//printf("*** OUTPUTS *** \n%d \n%d", out1, out2);

		Update(&m1, common_inputs, out2, HEBBIAN);
		Update(&m2, common_inputs, out1, HEBBIAN);

		res = CheckWeighs(&m1, &m2);

		//printf("\nRES %d", res);

		if(res == 1)
			synch = 1;

		h++;
	}

	printf("\n*** h *** %d", h);
}
