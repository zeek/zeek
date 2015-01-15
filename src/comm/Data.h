#ifndef BRO_COMM_DATA_H
#define BRO_COMM_DATA_H

#include <broker/data.hh>
#include "Val.h"

namespace comm {

extern OpaqueType* opaque_of_data_type;

RecordVal* make_data_val(const Val* v);

broker::util::optional<broker::data> val_to_data(const Val* v);

Val* data_to_val(broker::data d, BroType* type);

class DataVal : public OpaqueVal {
public:

	DataVal(broker::data arg_data)
		: OpaqueVal(comm::opaque_of_data_type), data(std::move(arg_data))
		{}

	broker::data data;
};

} // namespace comm

#endif // BRO_COMM_DATA_H
