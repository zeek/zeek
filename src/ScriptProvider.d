provider bro_script {
	probe function__entry(char *name);
	probe function__return(char *name);
	probe builtin__entry(char *name);
	probe builtin__return(char *name);
};

