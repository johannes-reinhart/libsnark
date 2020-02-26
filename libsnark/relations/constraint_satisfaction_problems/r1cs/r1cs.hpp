/** @file
 *****************************************************************************

 Declaration of interfaces for:
 - a R1CS constraint,
 - a R1CS variable assignment, and
 - a R1CS constraint system.

 Above, R1CS stands for "Rank-1 Constraint System".

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_HPP_
#define R1CS_HPP_

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <memory>

#include <libsnark/relations/variable.hpp>

namespace libsnark {

/************************* R1CS constraint ***********************************/

template<typename FieldT>
class r1cs_constraint;

template<typename FieldT>
std::ostream& operator<<(std::ostream &out, const r1cs_constraint<FieldT> &c);

template<typename FieldT>
std::istream& operator>>(std::istream &in, r1cs_constraint<FieldT> &c);

/**
 * A R1CS constraint is a formal expression of the form
 *
 *                < A , X > * < B , X > = < C , X > ,
 *
 * where X = (x_0,x_1,...,x_m) is a vector of formal variables and A,B,C each
 * consist of 1+m elements in <FieldT>.
 *
 * A R1CS constraint is used to construct a R1CS constraint system (see below).
 */
template<typename FieldT>
class r1cs_constraint {
public:

    linear_combination<FieldT> a, b, c;

    r1cs_constraint() {};
    r1cs_constraint(const linear_combination<FieldT> &a,
                    const linear_combination<FieldT> &b,
                    const linear_combination<FieldT> &c);

    r1cs_constraint(const std::initializer_list<linear_combination<FieldT> > &A,
                    const std::initializer_list<linear_combination<FieldT> > &B,
                    const std::initializer_list<linear_combination<FieldT> > &C);

    bool operator==(const r1cs_constraint<FieldT> &other) const;

    friend std::ostream& operator<< <FieldT>(std::ostream &out, const r1cs_constraint<FieldT> &c);
    friend std::istream& operator>> <FieldT>(std::istream &in, r1cs_constraint<FieldT> &c);
};

/************************* R1CS constraint (light) ***********************************/

template<typename FieldT>
class r1cs_constraint_light;

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}


template<typename FieldT>
class IConstraint
{
public:
    virtual ~IConstraint() {};
    virtual linear_combination_light<FieldT> getA() const = 0;
    virtual linear_combination_light<FieldT> getB() const = 0;
    virtual linear_combination_light<FieldT> getC() const = 0;
    virtual FieldT evaluateA(const std::vector<FieldT> &assignment) const = 0;
    virtual FieldT evaluateB(const std::vector<FieldT> &assignment) const = 0;
    virtual FieldT evaluateC(const std::vector<FieldT> &assignment) const = 0;
    virtual void swapAB() = 0;
};

template<typename FieldT>
class r1cs_constraint_light : public IConstraint<FieldT> {
public:

    r1cs_constraint_light() {};
    r1cs_constraint_light(const linear_combination_light<FieldT> &a,
                    const linear_combination_light<FieldT> &b,
                    const linear_combination_light<FieldT> &c) : a(a), b(b), c(c) {};

    linear_combination_light<FieldT> getA() const override
    {
        return a;
    }

    linear_combination_light<FieldT> getB() const override
    {
        return b;
    }

    linear_combination_light<FieldT> getC() const override
    {
        return c;
    }

    FieldT evaluateA(const std::vector<FieldT> &assignment) const override
    {
        return a.evaluate(assignment);
    }

    FieldT evaluateB(const std::vector<FieldT> &assignment) const override
    {
        return b.evaluate(assignment);
    }

    FieldT evaluateC(const std::vector<FieldT> &assignment) const override
    {
        return c.evaluate(assignment);
    }

    void swapAB() override
    {
        std::swap(a, b);
    }

    linear_combination_light<FieldT> a, b, c;
};

template<typename FieldT>
class r1cs_constraint_light_instance : public IConstraint<FieldT> {
public:

    r1cs_constraint_light_instance(
        const r1cs_constraint_light<FieldT>* _master,
        ITranslator* _master_translator
    ) : master(_master), master_translator(_master_translator)
    {

    }

    linear_combination_light<FieldT> getA() const override
    {
        auto instance = linear_combination_light<FieldT>(master->a);
        for (unsigned int i = 0; i < instance.terms.size(); i++)
        {
            instance.terms[i].index = master_translator->translate(instance.terms[i].index);
        }
        return instance;
    }

    linear_combination_light<FieldT> getB() const override
    {
        auto instance = linear_combination_light<FieldT>(master->b);
        for (unsigned int i = 0; i < instance.terms.size(); i++)
        {
            instance.terms[i].index = master_translator->translate(instance.terms[i].index);
        }
        return instance;
    }

    linear_combination_light<FieldT> getC() const override
    {
        auto instance = linear_combination_light<FieldT>(master->c);
        for (unsigned int i = 0; i < instance.terms.size(); i++)
        {
            instance.terms[i].index = master_translator->translate(instance.terms[i].index);
        }
        return instance;
    }

    FieldT evaluateA(const std::vector<FieldT> &assignment) const override
    {
        return master->a.evaluate(assignment, master_translator);
    }

    FieldT evaluateB(const std::vector<FieldT> &assignment) const override
    {
        return master->b.evaluate(assignment, master_translator);
    }

    FieldT evaluateC(const std::vector<FieldT> &assignment) const override
    {
        return master->c.evaluate(assignment, master_translator);
    }

    void swapAB() override
    {
        master_translator->swapAB();
    }

private:

    const r1cs_constraint_light<FieldT>* master;
    ITranslator* master_translator;
};

/************************* R1CS variable assignment **************************/

/**
 * A R1CS variable assignment is a vector of <FieldT> elements that represents
 * a candidate solution to a R1CS constraint system (see below).
 */

/* TODO: specify that it does *NOT* include the constant 1 */
template<typename FieldT>
using r1cs_primary_input = std::vector<FieldT>;

template<typename FieldT>
using r1cs_auxiliary_input = std::vector<FieldT>;

template<typename FieldT>
using r1cs_variable_assignment = std::vector<FieldT>; /* note the changed name! (TODO: remove this comment after primary_input transition is complete) */

/************************* R1CS constraint system ****************************/

template<typename FieldT>
class r1cs_constraint_system;

template<typename FieldT>
std::ostream& operator<<(std::ostream &out, const r1cs_constraint_system<FieldT> &cs);

template<typename FieldT>
std::istream& operator>>(std::istream &in, r1cs_constraint_system<FieldT> &cs);

/**
 * A system of R1CS constraints looks like
 *
 *     { < A_k , X > * < B_k , X > = < C_k , X > }_{k=1}^{n}  .
 *
 * In other words, the system is satisfied if and only if there exist a
 * USCS variable assignment for which each R1CS constraint is satisfied.
 *
 * NOTE:
 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
 * Thus, the 0-th variable is not included in num_variables.
 */
template<typename FieldT>
class r1cs_constraint_system {
public:
    size_t primary_input_size;
    size_t auxiliary_input_size;

    std::vector<std::unique_ptr<IConstraint<FieldT>>> constraints;

    r1cs_constraint_system() : primary_input_size(0), auxiliary_input_size(0) {}

    size_t num_inputs() const;
    size_t num_variables() const;
    size_t num_constraints() const;

#ifdef DEBUG
    std::map<size_t, std::string> constraint_annotations;
    std::map<size_t, std::string> variable_annotations;
#endif

    bool is_valid() const;
    bool is_satisfied(const std::vector<FieldT>& full_variable_assignment) const;

    void add_constraint(const r1cs_constraint<FieldT> &c);
    void add_constraint(const r1cs_constraint<FieldT> &c, const std::string &annotation);

    void swap_AB_if_beneficial();

    bool operator==(const r1cs_constraint_system<FieldT> &other) const;

    friend std::ostream& operator<< <FieldT>(std::ostream &out, const r1cs_constraint_system<FieldT> &cs);
    friend std::istream& operator>> <FieldT>(std::istream &in, r1cs_constraint_system<FieldT> &cs);

    void report_linear_constraint_statistics() const;
};


} // libsnark

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.tcc>

#endif // R1CS_HPP_
