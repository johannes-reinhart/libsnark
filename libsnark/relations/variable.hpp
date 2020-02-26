/** @file
 *****************************************************************************

 Declaration of interfaces for:
 - a variable (i.e., x_i),
 - a linear term (i.e., a_i * x_i), and
 - a linear combination (i.e., sum_i a_i * x_i).

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef VARIABLE_HPP_
#define VARIABLE_HPP_

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace libsnark {

/**
 * Mnemonic typedefs.
 */
typedef unsigned int var_index_t;
typedef long integer_coeff_t;

/**
 * Forward declaration.
 */
template<typename FieldT>
class linear_term;

/**
 * Forward declaration.
 */
template<typename FieldT>
class linear_combination;


/**
 * Global pool of field elements.
 */
template<typename FieldT>
class ConstantStorage
{
public:
    static ConstantStorage& getInstance()
    {
        static ConstantStorage instance;
        return instance;
    }
private:
    ConstantStorage()
    {
        constants.push_back(FieldT::one());
        constants.push_back(FieldT::zero());
    }

public:
    ConstantStorage(ConstantStorage const&)     = delete;
    void operator=(ConstantStorage const&)      = delete;

    std::vector<FieldT> constants;

    unsigned int add(const FieldT& constant)
    {
        for (unsigned int i = 0; i < constants.size(); i++)
        {
            if (constant == constants[i])
            {
                return i;
            }
        }
        constants.push_back(constant);
        return constants.size() - 1;
    }

    const FieldT& get(unsigned int index)
    {
        return constants[index];
    }
};

/********************************* Variable **********************************/

/**
 * A variable represents a formal expression of the form "x_{index}".
 */
template<typename FieldT>
class variable {
public:

    var_index_t index;

    variable(const var_index_t index = 0) : index(index) {};

    linear_term<FieldT> operator*(const integer_coeff_t int_coeff) const;
    linear_term<FieldT> operator*(const FieldT &field_coeff) const;

    linear_combination<FieldT> operator+(const linear_combination<FieldT> &other) const;
    linear_combination<FieldT> operator-(const linear_combination<FieldT> &other) const;

    linear_term<FieldT> operator-() const;

    bool operator==(const variable<FieldT> &other) const;
};

template<typename FieldT>
linear_term<FieldT> operator*(const integer_coeff_t int_coeff, const variable<FieldT> &var);

template<typename FieldT>
linear_term<FieldT> operator*(const FieldT &field_coeff, const variable<FieldT> &var);

template<typename FieldT>
linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const variable<FieldT> &var);

template<typename FieldT>
linear_combination<FieldT> operator+(const FieldT &field_coeff, const variable<FieldT> &var);

template<typename FieldT>
linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const variable<FieldT> &var);

template<typename FieldT>
linear_combination<FieldT> operator-(const FieldT &field_coeff, const variable<FieldT> &var);


/****************************** Linear term **********************************/

/**
 * A linear term represents a formal expression of the form "coeff * x_{index}".
 */
template<typename FieldT>
class linear_term {
public:

    var_index_t index;
    FieldT coeff;

    linear_term() {};
    linear_term(const variable<FieldT> &var);
    linear_term(const variable<FieldT> &var, const integer_coeff_t int_coeff);
    linear_term(const variable<FieldT> &var, const FieldT &field_coeff);

    linear_term<FieldT> operator*(const integer_coeff_t int_coeff) const;
    linear_term<FieldT> operator*(const FieldT &field_coeff) const;

    linear_combination<FieldT> operator+(const linear_combination<FieldT> &other) const;
    linear_combination<FieldT> operator-(const linear_combination<FieldT> &other) const;

    linear_term<FieldT> operator-() const;

    bool operator==(const linear_term<FieldT> &other) const;
};

template<typename FieldT>
linear_term<FieldT> operator*(const integer_coeff_t int_coeff, const linear_term<FieldT> &lt);

template<typename FieldT>
linear_term<FieldT> operator*(const FieldT &field_coeff, const linear_term<FieldT> &lt);

template<typename FieldT>
linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const linear_term<FieldT> &lt);

template<typename FieldT>
linear_combination<FieldT> operator+(const FieldT &field_coeff, const linear_term<FieldT> &lt);

template<typename FieldT>
linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const linear_term<FieldT> &lt);

template<typename FieldT>
linear_combination<FieldT> operator-(const FieldT &field_coeff, const linear_term<FieldT> &lt);




/****************************** Linear term light **********************************/

/**
 * A linear term represents a formal expression of the form "coeff * x_{index}".
 */
template<typename FieldT>
class linear_term_light {
public:

    var_index_t index;
    unsigned int coeff_index;

    linear_term_light() { };
    linear_term_light(const variable<FieldT> &var, unsigned int coeff) : index(var.index), coeff_index(coeff) {}

    inline const FieldT& getCoeff() const
    {
        return ConstantStorage<FieldT>::getInstance().constants[coeff_index];
    }
};


/***************************** Linear combination ****************************/

template<typename FieldT>
class linear_combination;

template<typename FieldT>
std::ostream& operator<<(std::ostream &out, const linear_combination<FieldT> &lc);

template<typename FieldT>
std::istream& operator>>(std::istream &in, linear_combination<FieldT> &lc);

/**
 * A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}".
 */
template<typename FieldT>
class linear_combination {
public:

    std::vector<linear_term<FieldT> > terms;

    linear_combination() {};
    linear_combination(const integer_coeff_t int_coeff);
    linear_combination(const FieldT &field_coeff);
    linear_combination(const variable<FieldT> &var);
    linear_combination(const linear_term<FieldT> &lt);
    linear_combination(const std::vector<linear_term<FieldT> > &all_terms);

    /* for supporting range-based for loops over linear_combination */
    typename std::vector<linear_term<FieldT> >::const_iterator begin() const;
    typename std::vector<linear_term<FieldT> >::const_iterator end() const;

    void add_term(const variable<FieldT> &var);
    void add_term(const variable<FieldT> &var, const integer_coeff_t int_coeff);
    void add_term(const variable<FieldT> &var, const FieldT &field_coeff);

    void add_term(const linear_term<FieldT> &lt);

    FieldT evaluate(const std::vector<FieldT> &assignment) const;

    linear_combination<FieldT> operator*(const integer_coeff_t int_coeff) const;
    linear_combination<FieldT> operator*(const FieldT &field_coeff) const;

    linear_combination<FieldT> operator+(const linear_combination<FieldT> &other) const;

    linear_combination<FieldT> operator-(const linear_combination<FieldT> &other) const;
    linear_combination<FieldT> operator-() const;

    bool operator==(const linear_combination<FieldT> &other) const;

    bool is_valid(const size_t num_variables) const;

    void print(const std::map<size_t, std::string> &variable_annotations = std::map<size_t, std::string>()) const;
    void print_with_assignment(const std::vector<FieldT> &full_assignment, const std::map<size_t, std::string> &variable_annotations = std::map<size_t, std::string>()) const;

    friend std::ostream& operator<< <FieldT>(std::ostream &out, const linear_combination<FieldT> &lc);
    friend std::istream& operator>> <FieldT>(std::istream &in, linear_combination<FieldT> &lc);
};

template<typename FieldT>
linear_combination<FieldT> operator*(const integer_coeff_t int_coeff, const linear_combination<FieldT> &lc);

template<typename FieldT>
linear_combination<FieldT> operator*(const FieldT &field_coeff, const linear_combination<FieldT> &lc);

template<typename FieldT>
linear_combination<FieldT> operator+(const integer_coeff_t int_coeff, const linear_combination<FieldT> &lc);

template<typename FieldT>
linear_combination<FieldT> operator+(const FieldT &field_coeff, const linear_combination<FieldT> &lc);

template<typename FieldT>
linear_combination<FieldT> operator-(const integer_coeff_t int_coeff, const linear_combination<FieldT> &lc);

template<typename FieldT>
linear_combination<FieldT> operator-(const FieldT &field_coeff, const linear_combination<FieldT> &lc);


class ITranslator
{
public:
    virtual unsigned int translate(unsigned int index) const = 0;
    virtual void swapAB() = 0;
};

/**
 * A linear combination represents a formal expression of the form "sum_i coeff_i * x_{index_i}".
 */
template<typename FieldT>
class linear_combination_light {
public:

    linear_combination_light() {}
    linear_combination_light(const std::vector<linear_term_light<FieldT>>& _terms) : terms(_terms) {}

    FieldT evaluate(const std::vector<FieldT> &assignment) const
    {
        FieldT acc = FieldT::zero();
        for (auto &lt : terms)
        {
            acc += lt.index == 0 ? lt.getCoeff() : assignment[lt.index] * lt.getCoeff();
        }
        return acc;
    }

    FieldT evaluate(const std::vector<FieldT> &assignment, const ITranslator* translator) const
    {
        FieldT acc = FieldT::zero();
        for (auto &lt : terms)
        {
            acc += lt.index == 0 ? lt.getCoeff() : assignment[translator->translate(lt.index)] * lt.getCoeff();
        }
        return acc;
    }

    std::vector<linear_term_light<FieldT>> getTerms() const
    {
        return terms;
    }

    std::vector<linear_term_light<FieldT>> terms;
};

} // libsnark

#include <libsnark/relations/variable.tcc>

#endif // VARIABLE_HPP_
