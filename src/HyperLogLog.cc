// See the file "COPYING" in the main distribution directory for copyright.

#include <math.h>
#include <stdint.h>
#include "HyperLogLog.h"
#include <iostream>

using namespace std;

int CardinalityCounter::optimalB(double error)
	{
		double initial_estimate = 2*(log(1.04)-log(error))/log(2);
		int answer = (int) floor(initial_estimate);
		double k;

		do
			{
			answer++;
			k = pow(2, (answer - initial_estimate)/2);
			}
		while (erf(k/sqrt(2)) < HLL_CONF);

		return answer;
	}

CardinalityCounter::CardinalityCounter(uint64_t size)
	{
	m = size;
	buckets = new uint8_t[m];

	if(m == 16)
		alpha_m = 0.673;
	else if(m == 32)
		alpha_m = 0.697;
	else if(m == 64)
		alpha_m = 0.709;
	else
		alpha_m = 0.7213/(1+1.079/m);

	for (uint64_t i = 0; i < m; i++)
		buckets[i] = 0;
  
	V = m;
	}
 
CardinalityCounter::CardinalityCounter(double error_margin)
	{
	int b = optimalB(error_margin);
	m = (uint64_t) pow(2, b);
	buckets = new uint8_t[m];

	if(m == 16)
		alpha_m = 0.673;
	else if(m == 32)
		alpha_m = 0.697;
	else if(m == 64)
		alpha_m = 0.709;
	else
		alpha_m = 0.7213/(1+1.079/m);

	for (uint64_t i = 0; i < m; i++)
		buckets[i] = 0;

  	V = m;
}

CardinalityCounter::~CardinalityCounter() 
	{
	delete [] buckets;
	}

uint8_t CardinalityCounter::rank(uint64_t hash_modified)
	{
	uint8_t answer = 0;
	hash_modified = (uint64_t)(hash_modified/m);
	hash_modified *= 2;
	do
		{
		hash_modified = (uint64_t) (hash_modified/2);
		answer++;
		}
	while (hash_modified%2 == 0);
  
	return answer;
	}

void CardinalityCounter::addElement(uint64_t hash)
	{
	uint64_t index = hash % m;
	hash = hash-index;

	if(buckets[index] == 0)
		V--;
  
	uint8_t temp = rank(hash);
  
	if (temp > buckets[index])
    		buckets[index] = temp;
}

double CardinalityCounter::size()
	{
	double answer = 0;
	for (unsigned int i = 0; i < m; i++) 
		answer += pow(2, -(int)buckets[i]);

  	answer = 1/answer;
  	answer = alpha_m*m*m*answer;

  	if (answer <= 5*(double)(m/2))
		return m*log((double) m/V);
  	else if(answer <= pow(2,64)/30)
		return answer;
	else
		return -pow(2,64)*log(1-answer/pow(2,64));
}

void CardinalityCounter::merge(CardinalityCounter* c)
	{
	uint8_t* temp = (*c).getBuckets();
	V = 0;
	for (unsigned int i = 0; i < m; i++)
		{
    		if (temp[i] > buckets[i])
      			buckets[i] = temp[i];

    		if (buckets[i] == 0)
			V += 1;
  		}
	}

uint8_t* CardinalityCounter::getBuckets()
	{
	return buckets;
	}

uint64_t CardinalityCounter::getM()
	{
	return m;
	}
